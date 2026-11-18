{-# LANGUAGE OverloadedStrings #-}

-- A peer for the interop matrix, written against the `tls` package.
--
--   haskell-tls-peer client <host> <port> <ca.pem> [sni=NAME] [alpn=a,b] [versions=12|13]
--                              [cert=PATH key=PATH]
--   haskell-tls-peer server <port> <chain.pem> <key.pem> [alpn=a,b] [clientca=PATH] [versions=12|13]
--
-- Both sides speak lines: the server answers every line it reads with the same line, and the
-- client sends one, reads it back, and prints where the connection landed.
--
-- The `tls` package is the only Haskell implementation of TLS 1.3 in wide use, and it is the one
-- peer here written in a lazy functional language: the handshake is an IO action over a socket
-- the caller owns, which is a third shape for the same protocol after OpenSSL's BIO, rustls's
-- sans-IO state machine and Botan's callback object.

module Main (main) where

import Control.Exception (SomeException, try)
import Control.Monad (unless, when)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC
import qualified Data.ByteString.Lazy as BL
import Data.Default.Class (def)
import Data.Maybe (fromMaybe)
import Data.X509 (CertificateChain (..), SignedCertificate)
import Data.X509.CertificateStore (CertificateStore, makeCertificateStore, readCertificateStore)
import Data.X509.File (readSignedObject)
import Network.Socket
import qualified Network.Socket.ByteString as NSB
import Network.TLS
import Network.TLS.Extra.Cipher (ciphersuite_default)
import System.Environment (getArgs, lookupEnv)
import System.Exit (exitFailure, exitSuccess)
import System.IO (hPutStrLn, hSetBuffering, stderr, stdout, BufferMode (LineBuffering))

data Options = Options
  { optSni :: String
  , optAlpn :: [BC.ByteString]
  , optVersions :: [Version]
  , optCert :: Maybe FilePath
  , optKey :: Maybe FilePath
  , optClientCa :: Maybe FilePath
  }

defaultOptions :: Options
defaultOptions =
  Options
    { optSni = "localhost"
    , optAlpn = []
    , optVersions = [TLS13, TLS12]
    , optCert = Nothing
    , optKey = Nothing
    , optClientCa = Nothing
    }

failWith :: String -> IO a
failWith message = do
  hPutStrLn stderr ("haskell-tls-peer: " <> message)
  exitFailure

parseOptions :: [String] -> IO Options
parseOptions = go defaultOptions
  where
    go opts [] = pure opts
    go opts (arg : rest)
      | Just value <- strip "sni=" arg = go opts {optSni = value} rest
      | Just value <- strip "alpn=" arg =
          go opts {optAlpn = filter (not . BC.null) (BC.split ',' (BC.pack value))} rest
      | Just value <- strip "versions=" arg =
          go opts {optVersions = pickVersions value} rest
      | Just value <- strip "cert=" arg = go opts {optCert = Just value} rest
      | Just value <- strip "key=" arg = go opts {optKey = Just value} rest
      | Just value <- strip "clientca=" arg = go opts {optClientCa = Just value} rest
      | Just value <- strip "cafile=" arg = go opts {optClientCa = Just value} rest
      | arg == "resume" || arg == "early" =
          -- A resumption needs the same session manager across two connections, and this peer runs
          -- once per case. The case lives with the peers whose client can be asked for two.
          go opts rest
      | otherwise = failWith ("unknown option: " <> arg)
    strip prefix value
      | take (length prefix) value == prefix = Just (drop (length prefix) value)
      | otherwise = Nothing
    pickVersions value =
      [ v
      | (name, v) <- [("13", TLS13), ("12", TLS12), ("11", TLS11), ("10", TLS10)]
      , name `elem` splitOn ',' value
      ]
    splitOn sep value = case break (== sep) value of
      (one, []) -> [one]
      (one, _ : more) -> one : splitOn sep more

versionName :: Version -> String
versionName TLS13 = "1.3"
versionName TLS12 = "1.2"
versionName TLS11 = "1.1"
versionName TLS10 = "1.0"
versionName other = show other

-- | A read that stops at a newline, or at the end of the connection.
recvLine :: Context -> IO BC.ByteString
recvLine context = go B.empty
  where
    go seen = do
      chunk <- recvData context
      if B.null chunk
        then pure seen
        else do
          let all' = seen <> chunk
          if BC.elem '\n' all'
            then pure (BC.takeWhile (/= '\n') all')
            else go all'

addressFor :: String -> String -> IO AddrInfo
addressFor host port = do
  let hints = defaultHints {addrSocketType = Stream}
  resolved <- getAddrInfo (Just hints) (Just host) (Just port)
  case resolved of
    [] -> failWith ("cannot resolve " <> host)
    (one : _) -> pure one

withConnection :: String -> String -> (Socket -> IO a) -> IO a
withConnection host port action = do
  addr <- addressFor host port
  sock <- socket (addrFamily addr) (addrSocketType addr) (addrProtocol addr)
  connect sock (addrAddress addr)
  result <- action sock
  close sock
  pure result

-- | The credentials, and the one a client offers when a server asks for a certificate.
--
-- `tls` keeps client certificates behind `onCertificateRequest`, whose default answers `Nothing`
-- however the credentials were loaded — a client that never installs the hook never authenticates,
-- which is the sort of default a peer has to know about rather than discover.
credentialsOf :: Options -> IO (Credentials, Maybe Credential)
credentialsOf opts = case (optCert opts, optKey opts) of
  (Just cert, Just key) -> do
    loaded <- credentialLoadX509 cert key
    case loaded of
      Left message -> failWith ("credentials: " <> message)
      Right credential -> pure (Credentials [credential], Just credential)
  _ -> pure (Credentials [], Nothing)

clientStore :: FilePath -> IO CertificateStore
clientStore path = do
  store <- readCertificateStore path
  case store of
    Nothing -> failWith ("cannot read " <> path)
    Just one -> pure one

client :: String -> String -> FilePath -> [String] -> IO ()
client host port ca argv = do
  opts <- parseOptions argv
  store <- clientStore ca
  (creds, credential) <- credentialsOf opts
  let params =
        (defaultParamsClient (optSni opts) B.empty)
          { clientSupported =
              def
                { supportedVersions = optVersions opts
                , supportedCiphers = ciphersuite_default
                }
          , clientShared =
              def
                { sharedCAStore = store
                , sharedCredentials = creds
                }
          , clientHooks =
              def
                { onSuggestALPN =
                    pure (if null (optAlpn opts) then Nothing else Just (optAlpn opts))
                , onCertificateRequest = \_ -> pure credential
                }
          , clientUseServerNameIndication = True
          }
  withConnection host port $ \sock -> do
    context <- contextNew sock params
    handshake context
    sendData context "ping\n"
    first <- recvLine context
    info <- contextGetInformation context
    protocol <- getNegotiatedProtocol context
    let resumed = case info of
          Nothing -> False
          Just one ->
            infoTLS12Resumption one
              || infoTLS13HandshakeMode one `elem` [Just PreSharedKey, Just RTT0]
        version = maybe "-" (versionName . infoVersion) info
        alpn = maybe "-" BC.unpack protocol
        suite = "-"
    putStrLn $
      "ok version="
        <> version
        <> " suite="
        <> suite
        <> " alpn="
        <> alpn
        <> " sni="
        <> optSni opts
        <> " resumed="
        <> (if resumed then "1" else "0")
        <> " early=0 bytes="
        <> show (B.length first + 1)
        <> " first="
        <> BC.unpack first
    bye context

server :: String -> FilePath -> FilePath -> [String] -> IO ()
server port chain key argv = do
  opts <- parseOptions argv
  (creds, _) <- credentialsOf opts{optCert = Just chain, optKey = Just key}
  store <- maybe (pure (makeCertificateStore [])) clientStore (optClientCa opts)
  caCerts <- case optClientCa opts of
    Nothing -> pure []
    Just path -> readSignedObject path
  let params =
        def
          { serverShared = def {sharedCredentials = creds, sharedCAStore = store}
          , serverSupported =
              def
                { supportedVersions = optVersions opts
                , supportedCiphers = ciphersuite_default
                }
          , serverWantClientCert = maybe False (const True) (optClientCa opts)
          , serverCACertificates = caCerts
          , serverHooks =
              def
                { onALPNClientSuggest =
                    if null (optAlpn opts)
                      then Nothing
                      else Just (\offered -> pure (pick offered))
                , -- The default rejects every client certificate with "no client certificates
                  -- expected", whatever `serverWantClientCert` says; a server that asks has to
                  -- install the validation itself.
                  onClientCertificate =
                    if maybe False (const True) (optClientCa opts)
                      then validateClientCertificate store defaultValidationCache
                      else \_ -> pure (CertificateUsageReject (CertificateRejectOther "not asked"))
                }
          }
      pick offered = case filter (`elem` offered) (optAlpn opts) of
        (one : _) -> one
        [] -> error "no ALPN protocol in common"
  addr <- addressFor "127.0.0.1" port
  sock <- socket (addrFamily addr) (addrSocketType addr) (addrProtocol addr)
  setSocketOption sock ReuseAddr 1
  bind sock (addrAddress addr)
  listen sock 16
  hPutStrLn stderr ("listening on " <> port)
  loop sock params
  where
    loop sock params = do
      (conn, _) <- accept sock
      -- One connection at a time, and one failing connection does not end the server: a case that
      -- expects a refusal still needs the next case's connection to be accepted.
      _ <- try (serve conn params) :: IO (Either SomeException ())
      close conn
      loop sock params
    serve conn params = do
      context <- contextNew conn params
      debug <- lookupEnv "HASKELL_TLS_DEBUG"
      case debug of
        Just _ ->
          contextHookSetLogging context
            def
              { loggingPacketSent = \m -> hPutStrLn stderr ("tls send: " <> m)
              , loggingPacketRecv = \m -> hPutStrLn stderr ("tls recv: " <> m)
              }
        Nothing -> pure ()
      handshake context
      let echo = do
            line <- recvLine context
            unless (B.null line) $ do
              sendData context (BL.fromStrict (line <> "\n"))
              echo
      echo
      bye context

main :: IO ()
main = do
  hSetBuffering stdout LineBuffering
  hSetBuffering stderr LineBuffering
  argv <- getArgs
  case argv of
    ("client" : host : port : ca : rest) -> client host port ca rest
    ("server" : port : chain : key : rest) -> server port chain key rest
    _ -> failWith "client|server"
  exitSuccess
