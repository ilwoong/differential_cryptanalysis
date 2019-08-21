import differential_cryptanalysis as dc
import toycipher as tc
import numpy as np

cipher = tc.ToyCipher()
dc.print_differential_table(cipher.SBOX)

dc.perform_dc()
