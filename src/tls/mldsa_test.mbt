// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// From OpenSSL 3.5: an ML-DSA-44 root and a leaf for a.example, 2020 to 2040.
let mldsa_root : String =
  #|-----BEGIN CERTIFICATE-----
  #|MIIPizCCBgGgAwIBAgIUR5NLiHlSeqbvylCQkvqzqxT4vVEwCwYJYIZIAWUDBAMR
  #|MBUxEzARBgNVBAMMCm1sZHNhIHJvb3QwHhcNMjAwMTAxMDAwMDAwWhcNNDAwMTAx
  #|MDAwMDAwWjAVMRMwEQYDVQQDDAptbGRzYSByb290MIIFMjALBglghkgBZQMEAxED
  #|ggUhAFcS8m/KrA+G/74Q+ROofvhsXHq1X4eXRnhEWEAuAzMa92N2Qe7lZW8wERa8
  #|UvcRP4jC55SiLlfEBk6lwXa7EsuIIBIEgHPR/H/RolzhF/h5oaizV+PhZKbMVQZM
  #|QG0xSof2S7s/kD7zhHo4b9HlpARmIdNi3MY1DRxYU8HqrOgciS7hwUXgYhFRUsg/
  #|Xkeg9Py4OrbMv8EcPLqblrYnBRWA5GvxBhT0XZzk9a39KWtk9H9b0XUNlrJE+RHF
  #|pLqKYwcQMg6+Q88gMK3SykY7/dB1LynSz6B4CiutRz6tXd1eQfqYNTwgmYq0A+yN
  #|FvYypTovkrQChNEKJt+aXawakk5Ny6Jcmkw75ipzTjqyZ94xDSEb6HIw+VENERtN
  #|7lbCesaR5HrqwVa+M/YH8mtpY2pD8m7DEEO1L5IOW4rk5SznFl5XwAhS87DUHFl2
  #|BMORTWCIXBSACstflqYVw2mC2tD98/54QIMuORrWG3OI71mAFx8XLzqsNBCrVHfE
  #|rV8uZlrk+kiqOSxB1jsIPWF5YtlF6AofsVLkIRBBDBzeSimaIKOeq2GO+Ape8zCW
  #|hlMvGm7zlOmC8f8zn7hhwq1xP01eOWye4MVTt8B+aXw4wKO2MI77YOPVCd34slyq
  #|DtxY8DEYXJO7NLaksCgJ24hphAY+hq5G8d53lJC4o29w+8w+1vpfFpcrHkO9ukEl
  #|gk9rYQm/YkmFMjz89H6IynRQguS42AKHO0/sznH9OGokfnvttth0U/mtzlRUUjSV
  #|QPCr3QVA/sbboALLxebVjcMXsyu4fCSxRQdfin4C5VrQuukB3HRZcP7bFiOpL+ga
  #|EiDdj57PoW+Ntl0pKfnkNK9u5ixXm9wMng2CazMI6ruv0k7/9d29p5WgkoUhnA4g
  #|5pfF2QhgwiGvaBAqkwej4eh4+YuFl3dzpW0KUoA2tNv91L7SnmerQkXr6VBz0tG7
  #|IXEzXf/Gd2cI4RFFfQ+M2/557bvKLXnahpoGizPxIu3qmxIbPKBeZkIcrhmOXHCs
  #|jO8C9bkNNzHOq+1uyeFeClp2GW1u/KJqIMG13+6VMlYDRxtnSPyG6hmXH4oalOAs
  #|JQYI9fy7SC3MWeUZb9Q8bz625rZQ0fgUo+PsJo379hP/8F7hGmjzMe8+JGSy+7b5
  #|qgbi2VMdRTevSStwrwbfnhuWkkmFjo4/dJVp0WNaNHjY+FBbtaP2Eq9IoqnIaZnS
  #|I6Afmj18S/6JCCbf4IE3d0LeFx0VDFu4/Ezl10AVDL/ms1OTOHBDTdNz/j/GYzqb
  #|XNvJiBXV46Em+iISxMViTMjWWm8wDYND0y4GqvVokbB6svq70MiX9PWKZA1d5dUG
  #|Dig1eS1cNq1Sg4yDyWBRxqn4uPg08sqgj1idKfcrktJ5Atc+wMyN7JEqKu92aOGC
  #|+7u3H7iM5xzKFMu9z5H+4loXfIeqxXith4t0121OKmWN8VivQVz+dS9FawchSUVB
  #|TpL/aED7ddxgB8iLNt7lnvkt72fXr2nf9TuI+c3dwzl9pT2TyfJqRexunbFPSQ20
  #|fXCuPOy7oeldXgWfMs23NGwcbB5ZJAsg71BeGAcoBnTRGQ390tvDGfmQYIs9KqT4
  #|dnkbzak+LD1NO5uj8oUmLsPXnY5jsNMwc6yoM0XDDZPztnYeBY/F3uFCgwClMIVQ
  #|HuDVNjjY3pM1U+1V+F9Y6GD5c7USfmPNqlbTr4ZUoH3okR8FiETfJG0X3kJ5z9K7
  #|4BiXX7qZJRY/zhBGyvVJk6OUhN+jUzBRMB0GA1UdDgQWBBSi50NaQNgz2VCkiBsv
  #|0XtGkFlg+jAfBgNVHSMEGDAWgBSi50NaQNgz2VCkiBsv0XtGkFlg+jAPBgNVHRMB
  #|Af8EBTADAQH/MAsGCWCGSAFlAwQDEQOCCXUAGiT2ojVtHftwM7L9AZYCAjeOszGg
  #|+Hnq+UnSVzpQQCEjubRFBmSZLfBBCaAoPkPSivVnuLAt3cexw1mDQYSklvZUU0G9
  #|Bznsa0Z0p5tfu0PSo6se9PXdOrOaCXKRw9zLXNL1R/8dahffBYMCTfP9+1zVv4GA
  #|MgL5CRDF5YkWv4FMMRljfOgqUJd4dXswQClvN8otBHVAfZKiHiCjvO3UArQVI055
  #|wZA1VQQMlA88/ynrgUef+t61axPjBRFl74axRC6cqtHA6ejB96wjX/Baqcei+Kdn
  #|1Hkuqzko96wHa3QEYuleHm/I6hQKnTMyP1t180oGHgwuWwLtDowjFL1adytlPvTc
  #|2L502s0jqkVrift2/LNJW34rF2i2Llobr1VbK366KsNBoW/iZx0pkezuHoD6SQu6
  #|RljnzNbm8XiRrbfcLxa0TYYqtCq/sGarb32rnsdKG/myKXeaGcQ+X/G0MtCnENh4
  #|m8PbJrPM+XVuKN514yfD5OOp/s4CHpiJL2ciRLJLFw0CB8vbn1Tg6B4B3v0OstV2
  #|BPxOV4KXzdaGIeqSJEeaytpYyL3T29/5btj2piBj/wFXIKbmsTYkAybxkfOKgaVp
  #|hMytuNqf0me+d54aTspUK899kWObsPG3x3yE/TZ6dzJG3mJ4KKN90LpmAezCWE6g
  #|B+wYxoQncyZ+DBp3mXOcADyMFL28R79/5wjDuAA++j7AO4Z5uhQAYpENbGaYeD3H
  #|P90hANzRehKsBPJavckj1Y/8cIA24/kRQ6hlNGAy6RJ3j4i94Xs9loRYP2+sJlQu
  #|Z+boJyAvWeUuwVQBrtrP9wEpj8rFAr/5W0G4NKDKdvwXUnA2yFEzAxwldXbekUYe
  #|F0qIFaIxpVBH3QEZZmTGYY/41IoxjkJ3jEpnajtXhsl1mxyaFhagijzu57b/w4nt
  #|qPAPoX4cVlxeyKsikR4k+2cTpi4ugwR81AId+OjEBr7NZlmxKG3hlb0vX+3+58cb
  #|YOpR5sZcf6GvX3Sh5bQ57OPOkyci5xBAjzkY7s8A4SRl2U7cvLYAPLqYNhT8nM6u
  #|KqGGtQHmQu1aP/j0S+xS3xxognA3tvp88DRe/AAV/hpln+/pJ+zlfCO8zLuOyvy3
  #|QXG1HyonkBZWTmD+lB0U92AsaAlY+/Xc6Wf83xk5yp9cOSMe67rFLQOWOLFltsSn
  #|g4S2ue/46Z5CA1566qWCw0cz2ypz59o9APLJTtsIqVwbM3wOQQWTH6gG3M7aM9i0
  #|qoKVGl+BD33Ou35dP+MTAXLuHTdm720lt/SCj1rrVz2GZdOeJQpiQpKqkGhA39qN
  #|yNZV4qqBsQFU8zEgOFChWYbLCwR0+h24I/GEd47nM+5IPFLvskmub3K9V59YxJR6
  #|zRbbYyuUaLioS+V6yBVP6YWBgMokdRefVNp8gAZ/A3v8teLZi0ApKHE/jHwAd6zR
  #|1mwTu6xYqRnkkKbL/gF/k9xEgLJJmAFTtacP2QuzIXNKOSUZRK0IznxiKRPMUphn
  #|SUsG23sKOANJ5kj5iHpSxSvpbby84aBYCCg1BwE5Ouhjh+xg5K0orITWUHvpzYw9
  #|B0i7/rPyxp76Z/Unyjy7s8l8fSfjcbgQGY7l4HoVaPmRE54wflAXcd8g/cxdMO9a
  #|UVgPwwVx760e/DjnKYnG50ERGRu77bFHkyA78Ev1ajLgsuQL27P+085GoOwDIc5Y
  #|foWfa+SFdr3118YxghgudiMtR6ZYcsUFH7aTwAsJWe4lxBXVYdOXciTs5s1dYYz4
  #|KZjcE76KR0dLrvEoFOJsU4t8dMg0t7BMUIK3m5xFABvYeD1zKzlW9qoc3DhOcmng
  #|twMS2Ge2Dw3qROW1fqSn36K5QBoBm8A4Ktyd9jTQkIcfc9oOFc9XHnu6VljjM3WK
  #|2QYJjOpY3XwzHahL6Gms0nVeXWZHhYwHgYlLVHkNUEdYevx5QKu4ZypXDF4T5dWu
  #|wkTO/JHXOcfeTEccIIvcQq8c6gPiDbrUGaP39yYl7VAmI6H1k9bnnNkJPaQhz6e5
  #|8cWd7fkNJpJ4d6qHlohM3jmOMVUjnA9aGp555Iqsdd/Or3JxYQxteCJKDumTgN1v
  #|akILdcNQ4xPSpT9GZ5r873ZyHWsvXri5wBKQg20zNAx073gTUqoXEryyC50w1D4e
  #|Bn6fnoMwJS65Br7d3+wZ/Gjg0lJIvfAEwoNs+fW8EFRhQEDA+PanZibnamsxcvuK
  #|dlbAxIuRAFjlLuurchyfLJYe2RcKucObtc0EcqNNKr5Qbc/rfpCo8Dhtfa3Nh1s3
  #|jYRd0Dob4d1s9BXMKemtxL43aFU6soTcIxxbbWtzfmTJO6dW5NeA7vfdM8MDhQJT
  #|ahI4omlVjMFLU9Ld6EATUcggBqmuMhQe8/D6Fa+K/bayY9Kz33vcUmZhaKyyMFTj
  #|aK+FmW+13V2Dcu7Bt89fIS+Waz3tBPBuDgnGhIWawjjJ6cAme7IJlBib2WWF4C4c
  #|g+N7XZZSYEkdiEfhMzPcs/9cFHW/TubjpPaO5yLfcVg6gVXaEWCaP1NZf6s9qI4y
  #|IR4AZhH9ZRFMHkJuJQ8Acety1CFtk5L6e4Ep0Fvgs/+uOITGR08DaWTOjGNV1Dsj
  #|jfa7GQSlaQodNYHXPE30ioeMZflb8DeykI+ORxXZTp9Y1M+N33Nsq43vImyjLWYL
  #|tan8kEe7hVPRMKS5XoXB5TgVmWPLUGVM1W8+UgEREtPg2XpDNrJw/FD9fIktOr1j
  #|BlhQ+t97YLEzX7OYp3vab1NLakp2mQ/jPtH2gwTsqa65T5mpzQ6k6Lqcjmy4r74f
  #|2eK2KhZO6Rixbcmn27lql1OBjTv5KH27nl2z2tjzta/3qT4wuBimvAmor/5UvLLo
  #|k+LNhzwHKYxu1PHXKQ5Sh+jw0OPtJmlZIDh0Dyoqjd2fKt/9DksEVjbPOZQQ249C
  #|ywkVwCXpZSjzTj55RnOYjeSKDSjL+pdDZbPsdKdaPVI2ZTfzphv2CBPsZGhdvcRr
  #|KAmapY1ad395i10WHMZkuT6CxTQ3E+aV7ikBrYTQYdVWobMIIC/9tQfl8CkCLr/Q
  #|n6LVes6MzDpRZpiy/mtLD3h4T+VC4ZnXKsLWLrN/DjjwdCnbBA3U/eZRrPoYZWWu
  #|vBtXnmQGrpiZluwKDxAwfpOpr8bV2S03PEBHUWp1enuAr8DD2Nze6/z/HCE7PERZ
  #|bXJ6f4OOpbO9ydQHGR8iKDBCS2uFiZaev8HE09v9AAAAAAAAAAAAAAAAAAsfMEM=
  #|-----END CERTIFICATE-----

///|
let mldsa_cert : String =
  #|-----BEGIN CERTIFICATE-----
  #|MIIPvjCCBjSgAwIBAgIUJIgKttx9FmNOuwaWJfUmPCPB2vYwCwYJYIZIAWUDBAMR
  #|MBUxEzARBgNVBAMMCm1sZHNhIHJvb3QwHhcNMjAwMTAxMDAwMDAwWhcNNDAwMTAx
  #|MDAwMDAwWjAUMRIwEAYDVQQDDAlhLmV4YW1wbGUwggUyMAsGCWCGSAFlAwQDEQOC
  #|BSEAtd/xfTACN8Lmqn7g/3BrzpRpTXHWNmieH/ycFgJoki1Ebokdo55EF6GZJk+d
  #|Yi9vE4FmIVCJ65N2V/7K7Iun0wc6glIKqYWtG3VEmohZudiV8A0+Ted3QJfMGXkW
  #|C2vGrmNEmNWboplmDYBVyTbbIg6H6OBDnf9piN9FpMUk/H+ERu6vwpK9zjNWp3uX
  #|+Xupyuy6jLEeRsCMnEcDu0P4iUKr/gt5xvjkwcXB+tgsB9DhB21MFs1jAH5aMLOB
  #|IF1B3hX2ncRd8GGgIjN9RLmY/LIYZpygPktzF3pb10PeNeziHt7FOej3NnLDFou4
  #|bXCUIx9GUevdtORGDN8K4oZT63is3o4JPhOGOdxxJBoeALTx8Dn1vOYG2mjqmwW+
  #|3fj2BoDSjCoiaSJYSWSgtRHuK7HoY5Ld8nAt3iCNPTzJf85gEKfdpFGsWIXbJSeD
  #|zo3lKvTWPlXYEv2dnFpdbkxHheJUwL34Bqleb+DIVkM5Njxh2iVXstnf66JiH4eB
  #|hMyY485MrMD3ODVbZj34lYn2TW6wHGvnp+XZxdwZT/AFIcTahprs8wEMEjRwlkOi
  #|Of8G7wC2PeBFlH9jKUMTNH6NgaQmWYWlz4LCAIcoEmWG/qTMBc9awS0VfD8Hg3IA
  #|Ube5nc4Wa9REJgQ17nZ0pgJL+RcXgXxOmhm+IIm7dwdYGuQwNUNpQWbk++uNogGk
  #|VooN/HPI1EHcBreTrMkJ6FbypUZODLepVblhVt8Sv+3x4uQhUafGvFSvnZcCy04t
  #|mdu6HMhO5X8jVDwWXsZdlAP5JcauhhZvzeBUPQKQreeUeay/PnQeKaw+zPO1Zmgv
  #|apOQhhV40diXYVoJnB9sGNEJ8X1xUde8iIR3TVsHCmPx0b8kclkEge68n795FFTj
  #|Aedi5JVxVnchtEwTfKKT+pPLL88uGFctfVuPAjmGMD0zquQLjoncr1QRlKsCpf6Z
  #|86+0UNHpvr6okq1tmflTgDEa5TYXf+5iW8pV3seB9TUkxd3MPsdixIlVCn5B1g9U
  #|i7fJY8fmWJMhXaL3eaIPcbO+YJI1oaXE7KI+/VAqQr5P5K0LSTknl6uxfWSnXDs0
  #|+Avj233x3tgKSgnTJTE5FO7wlCyjhzME/1ibbdhyXGrQq9IgzyDmNwMAltMoGsRT
  #|WlfOqBsUBU1OAM/ucI1BCbDsZx+zQZm19BzqmKYpQuzl2jexu1YczcWVxKvYHINu
  #|V/B2OIMjhuolpco4vJC7XDV3mxAWPIXjtwhYBjZBxeTvZ6vQlW0CQ02mPhLff5sW
  #|gE1Bb6QcnJLlDHdkAPtSp61bnZeZSaaceouVP7k63aIfRCvjOCZpuQLMhXi5XYYo
  #|csHzfF0cd9vI84uEYIkDKJ7W3PECCCk2NU6Iv4Pp5PMcUeQJRqnPCHiDGIo5I2Ab
  #|uHueBXW0P8JzbfTLO1biqskgcPYmlYZ+bjE9ri8RQOQfSgiVnNbBeePsbn/j5hri
  #|KeYbnm8s63HjnUgBzOs37x2Fpn+RtyHT1f91uHSYUhSAj6GbFnszJnKlLUh+PH0g
  #|EOkIDXLGQ7ikEZUusIh5/Ja6qm+IEtsXsj8OWjhIbOlGvBjS6o3xypT+CDy8I6H1
  #|8Kem71phmYl7QepsSxuI9IY56DNCe66pwDtplXMqRnd2T3IBwRUcaWCOlyBNV7Ap
  #|qdbwDXOb+YUaNAyGM8NPu7gQGX9LGamqUY4B6364nsli0wJYpbie37C09C9TpHlX
  #|amFc0tWQzmv66nOtOC/XnpbAZKOBhjCBgzAUBgNVHREEDTALgglhLmV4YW1wbGUw
  #|CQYDVR0TBAIwADALBgNVHQ8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwEwHQYD
  #|VR0OBBYEFPXEChgX0E1D7nqF6wGc2mg4TFnpMB8GA1UdIwQYMBaAFKLnQ1pA2DPZ
  #|UKSIGy/Re0aQWWD6MAsGCWCGSAFlAwQDEQOCCXUAebeYpEarSeZuwqnc0pT3dU5J
  #|e4yAZOh3fC827GYrKmVCQiNghCk+2gVm0vbtBUFu9Ya5+z+T9EZstlOiz+3qHSRV
  #|zLXw+m2/mOfX5rqVGvWtG2TzvqLxznZfZRpzyYRHvk+lghnKIy75bSi9sc9JrHv3
  #|rQnP9yK+99+iXS5fv7XyD/AO0i5l9ucJQGaZS9zKOiaMa+QrMmD55jtYRYkQQADN
  #|VEYi5Raby5YduOjvq1Zb6EZ5YSEwJa1WZ+lFc3gm9dvQkEVSNnp1aU7HYArQT/qQ
  #|OGXadTEexJ5+2sMZG3KhRqRKDNA6kCQqa4Q4+wZWPilQNR3rUMSecge7RqovjnOS
  #|xsyxbAv/x16DNz1lLHrSnoQFeJI207dVRomSHQQhyvQVKkkH0/60TjXCBNCFUq14
  #|4oIkALQ9PcbeCOA5hMK0R+kpuwyQFDT9TtTb2JcQlIg4NdURiecJcBqqkGmvIaoo
  #|9n8WItGOBZGAnzOkMmeHy3I5mWVjGa8YPyMH5mJtXzVBkPOp2YsHZm+w2BTlGze+
  #|8Qs1R3XfAPXSioUWQ3Eij+A2ljTD8qRStj6CZp9xzEk8PC97Wdk9ND1/9T5GrO8h
  #|BXXRbPAhHgeqogFPYsuF1Dbo+GSs9sci9yMquGUTKuq/vFMJMXoYI9+KvX9t8g0h
  #|6i4pSAX7PVuD1Zm7miE8oyVhGp9zD3KOB5v1UPn18XDWEoBz6P51vjGuaZUVSa4u
  #|JbOvsU9SNg667x/9xFKSniMjyu/422EsW7KNQr5+kD1hApndHM73fPzHxJN9md9l
  #|GYtYr00v6JpcRYriRTRyUfRzOHS0g0N6VN+rPyJYUHQ2L8jBsERCwp+HVKPCiRG6
  #|DlsncvRqyq5fDqQpnrkqQD2UDjNGB0rQBAJZJVGN3CgE9SZGiYqBZLIm3c9TL2q7
  #|o8nbKYin9ZddiMwE5Wf3yNZokh9i8kgLRWwjibHZ95DGcPHGVaIOGy/gDEMTtQMY
  #|4tEZ4ACV+kAwVCcRm3w0e+kuBeVr1kmIcCfqLlynX2SpDZL3KsaKxESrJltzcBuW
  #|5cqkN2w7FJERO46D5866XRvxyUk10F0TJsWPG2taEOLa3slnAg1xwEOTdx6n2vac
  #|rOwboEwRYZRQ1/3vJ7ZMkkcGjeneFdz7blBkTlYcwbPoC1to0oFTrMYRHG4Smuib
  #|pZs8qY+rzaGgqHAyfwNF0zRtWO0VyZ4JW7BOSyWbavznsY2KDpl0HvHkFr2UEqmy
  #|yMEeBETnVIAMtD8Xc6Mibr0kfEEEDrGympWcCvgiv8lnhlXM7kj39wnRXE5Mjg+5
  #|hsZe7nAZKcMUpt4KxwRs8Ic4pUEpWUVSa7aSIYDZxZUP7OBQlQhEVukcapZpeOdt
  #|7wS6w+R9mCBY0M8HDMFUM44MkAO7uAaMV2S4Qei3YxMs7jfPu63FJpll5DCwzbpI
  #|lQm+UhH1I2kBHbTBvVwlZQXrnZganGm3eDO7VyG2osJHemawUzqMg9prWwoqa4wp
  #|iIjCtOXaIeNin5/5IqT88UT1UVEF1RSWcCnTcCflPc3/q0h2BW1D7iEGnfWK+Z30
  #|KXK8JZeRS11ckLigSTEjnj5FJa9o76Jn2NrrlfG1ptQI1TBTVeTruVl7RBL+O6u0
  #|qd7cCl1Yaqlqa0498sRRaqyFlZJ1FT7nfB5umC/X44BWULsKt4NfHv+xRygdos1a
  #|Muv2xTxZEsfgOgw+mfDcMs2jYKt+FXfod+JS4gbETi1aXn3604EsAaF/HAVVCRGK
  #|J65/fsFjXQxTauUQCW7J1/ROyv0sstR2k/7HN0h1PbLtwTFNfHkJGsA7EwM9z4gh
  #|qImddvq5J6bSCaelRB3SeveeAkpBZ5iqJdkMjdFLfmBaDwurEh9WHy//dSAe6PgL
  #|3lMIwfwzOAJQlKJAKTY2QDNKGGvSbjzEFoI8NX9B3K5qek7QFxULtYjg2lgWfh0m
  #|JH2T5t6cOmtW6DNN9QsL4AhOc/zeBt+P8PQVGZTdgXRuHJ1CL9WRxE86uVxvS4+I
  #|wNc+XYEPauRPHcZSjDXYh567r3BLtNoUE5O9l5s2BTD/PO50V6DV6h9yvMeW5f66
  #|6Fn4a/tHCb88+mT1jZP8o4DnNXBvtjKDYfJHSASd+kBKIULjgoCK17+YDf/4zkiT
  #|2j4DbSP7eW0nH4xEGivjZyQ9uMoh4r5G1Bl/6TKZ1bXirU4lZYS1pECCTheH328k
  #|jLlmFIu2RMWj0+q147YMgJws6xIGITd7Csm7A6MVbcqVuGXPlRNm7nrtWEaKB5YD
  #|ORk0o+0tM41h/IlfX3dfl4fAPFc0h7Jt/PCpv1iMKAEME7OTR3QMZaCziOKihTOd
  #|/7FcsfS9XHqvcAcp6UCIv5EqsdtxYpvlPVmZZ1CjUfMTB1uuh1+ma64cVWdAiAmF
  #|h7yh6/XViDYym+Gb0ge41gtfydIGu6XyOJTjwyycnjfrhrbw9k/YL6P9cr/UPubI
  #|HsSwCQDGYM16rDrSiYmT0g8mLDMImSfpA372MW1Fskmq6+Wd3wB5GWBAo9CE9GXm
  #|fSp/4XHDun0YOfNmse103YjWymlhhN1aB8Eb7hJ83DCSMyOifGAl/XRcy1mOB9ES
  #|xJobk0WPQKuZ+RWdQLGIC7XorqXgTf7S8nLtCrdQDq8Ew++LC0h5KDI9ogtL2gLM
  #|w9fxFOTdVWiMZ22iIuLW4f6cG2f8ayDZvnmOl6kYT6xThJ3sho7Z5tLHECw2cZBo
  #|i4jk3iOJTrZfvtqkjS2Bg6/gMjGe35p4VKBmN/sY4F+svdGLs8OAEqsz6j0IDajH
  #|THI17X2BUEFRVHcxQyJqLfwDn63RrvtjQ6sWN2uo9i2D0Y9opwYwc1ALC6fPaFFn
  #|392rdbvXLNh9oX6XyF0ibcDkiqEVR6M6wSAXOJ9jcmbxAw9fA9rcvwz+mw+qZF+f
  #|fVsoVc6V3obME48oUb5bWEA1jlMGibUNEk2JUwNlmACxG173sR54TnVikEfp2NpG
  #|ymdFn39B2XkCtPU0+leu7d03MrzINQ3M2NHKIertgVdPzLhcNo49yMdWyPAWBgwO
  #|QgwcPwlED/A3j3eCfygi/bkfzAA1e6EPexMog2dksWEu5+my1l4uTFvSlcYnFDTd
  #|IuzRby6e/NL8BhDbpeYKCyo2PUlMVGVogISGkJydpsve3+Hi+gsZU1mFiouOnKm0
  #|yODt8yNcYG2Cj6aqq666yOwAMz9KT3J6foaJi5bC2esAAAAAAAAAAAAAAAAAABcm
  #|M0I=
  #|-----END CERTIFICATE-----

///|
let mldsa_key : String =
  #|-----BEGIN PRIVATE KEY-----
  #|MIIKPgIBADALBglghkgBZQMEAxEEggoqMIIKJgQgSEGjaD3qJw0LuBdtMfrf1khX
  #|1jff/z8S/aMlmBQidgsEggoAtd/xfTACN8Lmqn7g/3BrzpRpTXHWNmieH/ycFgJo
  #|ki2+qP11PxN7EyK+3cbyC/4zviEq8j9GKkLlN6fCMLSDSgo8D9kpOninmNHrEYTt
  #|V+SwcQ8nKfd6tZXx3ZDorS3vmGCPdF34qEjklkXB3hoXNjx4J9Y/sNZExKl3P4wA
  #|XmJiwlCDREycIkBKJCIRQk6KtkEaAUlcRGhBRgkQxFEcKQUEtYkBt4BYFgiRhhHZ
  #|AAXjGHHBAFDcRAaSOGUBgwiBInCaAABROJJLFiIROYwapQgEswEZlIUcGEqACERI
  #|qFEQKSUatIXiyIQkAXDiyCAUxoxjRiXBCAGkNG0BqIEYoyCjJmIRxRGEwAkIBHJc
  #|MmXKEECkGGFDFlCEsmnKhmlCKGXQkmEZAlLTkAwbkWQZtSUaIy4QOGCaGBFEBgQI
  #|QkIMIYqEkoFBGCaURmEIgUEiNiUSskXSNIicpGTBhiTKCCwYs2DUmIGihC3EAEij
  #|NG0kSQ1ItmFkEigMl0DYiE0ZSHIRmG2DgkFZtEhcAowgiWyjgJBiGCZCEIVYpjEZ
  #|oXAhBXKhxJGDBDBbkoyCpkHclCgKlSHJNoghIkiTMIRCRhLgBGIkCZALQoFYwEFM
  #|wBBQEhGJgGHTEIoDF1IaR20YRUUhQCiENpKSMBCaAmJQFCILE2wRRSgCJGYYQZFU
  #|piQEFAwYsyRQQkxggEwLQUkgqIzDBELQxIkkqRACRjFKRizimHEayGUblCQRlkgk
  #|JQILAEBiJCYbkFFZIkJKNDAEmC1MRo2AECDjEJIkA03aiISbIGwKN42BEmqMBCqC
  #|kilDyDCawkQkIC0bICUJtWEkGSUkQIjIAAVYxlAClknSEG6RMgjjEEILBi1kJCSC
  #|IAbCpHAkQAYEt0waoCDLJmALMBIAN1IhJCqQOGkAAwobNY4YKHDQSCHRCJFJRgRL
  #|JkUgNETUwiECIWAbmJGChoALFymUlGBbNE0SpUShpnAStAzRIjKMAoYQOW4CmY0k
  #|RU7LpGCMkAXRMihciEkAJjAbCUBJRhDQEkLcGHDgICxcKIoAtxFcopDQCCyEoiHT
  #|BEFbookMg2lAqI0hMjGJGCpgpE0KR2aJxggLB0ITRErUxIXZtnAiJFCIOFIhRGoa
  #|giAaOJKUNiwBSCIDAogiQTAkQo1CSG0jBAACoIDjRAYMlDHIuIljtBEUBUhABCxT
  #|EA7gZgpJPF4ri5LlbWWEB5BNVFSCyCQRmNN/294YaTkgsiOxmbDD+Dt8pA0A1juM
  #|U2ISOu5anvUSzTfq5Rva2zsvXA6EyGrDN+FroeLi0VE+6mrrAJdWFdc7qfxG2duP
  #|W1meQMi3AvXDsrmvCAksAW5LXpYyhhkNjqJhZ3BmjwgUlNdYWMqckHDAu/33QXwb
  #|qO7BcQ6aUMM9hHVBGcc9aG83M5WBnsF9Om1bZ2auL6FAZGcUjNaUZnVwkaouizXS
  #|Z1IjI4FMtqaNebXBe7XNu1rpkCNmhmcCZm/Gz1+t4z1DSq0tew+AWQC+e3yrxve+
  #|llFU+Rw8hhlcrWofsJA7c1bZ74IBKAJh89feeozz3/cgX1t7oPyDGGq4+BDgTxDo
  #|bUqOkCsKe9d42J8ltljbwY5PEg3Wwu/GoO4eCmBOMHwGq0Dkr/fsx3h3iYphyQsG
  #|3/32b9Svv67gwT8NAVQm79+fM6hiFxTtLA2aFD44mZqET0Y3mOFBFp1iMx2Bb8vs
  #|BkSCEI5zz5KOuht5T8We/OLzpmqlScvWt16pYvRYPKRfJPbFXBR9vzRKAsOb2leu
  #|N9ibb7aYe4g8zLsLur2VP0kSBPQG+Us6g10uWmexdTOlIRLOo2izNI33opMpQuYj
  #|OpFqtFQUEK1l/bk0Ethe2mUBmQYfArYR9cgsKMKKzIaDfVgF7QcEhlXz8DNCsPwG
  #|zPMQL7vTN6vl8151CanN/GpXxb+Wx1exGJlenJzsR46jGsmW1Ng1K883K49jPbsE
  #|f5cjuQvY9vYhZuoFHEyT8FH6p3kVk1ZgSLj/cVVq1wdGDUYGN4syN0C14xJaYbU/
  #|eetfEC3yXT3OCOR4eavrC/RXCEhgcZvJ8idBUVc8GEIRGHqGyW5CYfPZkV+a7nW9
  #|jfixkrHx67iimjzrN68HFsocTP+O9pHbhclei1/Nh5EwtUO47sPXwisR+aHBUN3P
  #|lfQvA6GeRphkYpQ4MgL7mXIy1+MdJ9TmR1BL15vEAl3hr1lKD+RhfsHH7GzWkWax
  #|iJz+M66vlONbuhqv8z/YkEIJ8r/ucjDus4WTsbGTm+PfGaRYRlxM1g5urPhaIBOZ
  #|ZyGXKMaegsXYMJ2WUrx82Z5bBODKlJ78Oug/RFxntqM9lAknjngsX+EiRtMhTBEp
  #|Y/vkmSTS2I/F6eY0WKVh7G47gzZ3yYKoXTJiwiwEwTqULvAJ+oPza8oLUTOrriC+
  #|BpDhb1xKH6fw54R0NqGnesR+KxumEr9e+oJ/KklDRrRV/QEISNzYRVt4/QCcNs12
  #|zao9oh2ZxE+oeQfnhO0i6HNZkG30dBm04J7QjQTCo6mfbzd/9DrkxcxVL3ekRboa
  #|a3RrQMIc4wDTpujyns8/aavv2nuiB6qLulpOJsY3FGK89OIRAYlgowq/3oEEZoIh
  #|lc31zNpqSbC0SN62Ct+o9S2+Sab6qvYMSfPqx6qG9DdPescyhHDUBeL24p1a4ssu
  #|HvlaIhlNhMw8RJhLy14WUWf/nnpQU6aQcc88C8j775S4id/GdM0Afi2awvn9wlcy
  #|3HD7QtU5gaC5kFb23OBk2zUTRjyOwEEv18URBBL+02tSKah9waly6vbZRJ0l4rPM
  #|fCjtgSKxZPCB/4rQsQzkeG017FUq/bl26m2JgyQatca9pjCKkpPxI/YbgjTFx7BH
  #|jyps1gYbMF+1PJqdEOtBhvfhkRwgnMHHPBsL7/kzI/yuVmXxSuAqkNupzk0d3jdD
  #|0/f7e3HMrbgHp+ENuhO1igyB5uj6n5T0NQ2UPqDaAo+EmmEBSgfAIXoGRh6TI+hm
  #|btomKYzl3pa2jReeA58LZajNnkv8AGi3ufEmKpHBKt2vzqlR4KhecULqdc48u/n0
  #|+MC4E+66Fb+nehdl+mEOfK6ZSfusLW31LGyD0/RGgYXCKLEbIchos60z6WqsCqLr
  #|CiPJr1YV/PqBIR0/thto0D4qPBu/q+KsAy0gGTayMGGZIzmgzfVgZBf1QToVPrDy
  #|ZDgTFY/Jleo5UvtMjeiAIA3JjOLUzJrrtZuUHRB7UxcRWhpcRUtXhOHRY6Nn3rnE
  #|nkiKRicRb22osNtcv50caiDdkBLR/xoLFNSW6C5Ru/AOoMpip/9YjSRE77QD7coI
  #|xaCZ7BbWrVGKC+XiDYr2+vHwt7jae7qZKAGgvQEPpXRB660wD6HKJJ5PYeBTcphA
  #|Ir78zySQ5XXuKnQd2Bthbxnzlc4WDxeaLFAUo+B4w21UAQ==
  #|-----END PRIVATE KEY-----

///|
fn mldsa_server(versions? : Array[@tls.Version]) -> @tls.Conn raise {
  @tls.Conn::server(
    @tls.Server::new(
      [der(mldsa_cert)],
      key(mldsa_key),
      versions=versions.unwrap_or(@tls.versions),
    ),
    rand=rng(3000),
    now~,
  )
}

///|
fn mldsa_client(versions? : Array[@tls.Version]) -> @tls.Conn raise {
  @tls.Conn::client(
    @tls.Client::new(
      @x509.Roots::new(certs=[der(mldsa_root)][:]),
      versions=versions.unwrap_or(@tls.versions),
    ),
    "a.example",
    rand=rng(2000),
    now~,
  )
}

///|
test "tls: an ML-DSA certificate opens a TLS 1.3 connection" {
  let client = mldsa_client()
  let server = mldsa_server()
  shuttle(client, server)
  assert_true(client.is_connected())
  assert_true(server.is_connected())
  client.write(b"signed by a lattice"[:])
  shuttle(client, server)
  assert_eq(server.read(), b"signed by a lattice")
}

///|
test "tls: TLS 1.2 has no scheme for ML-DSA, so that server has nothing to offer" {
  let refused = try {
    shuttle(
      mldsa_client(versions=[@tls.Tls12]),
      mldsa_server(versions=[@tls.Tls12]),
    )
    false
  } catch {
    @alert.Alert(..) => true
    _ => false
  }
  assert_true(refused)
}
