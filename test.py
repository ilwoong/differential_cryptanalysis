import differential_cryptanalysis as dc
import toycipher as tc

cipher = tc.ToyCipher()
dc.print_inout_table(cipher.SBOX)
dc.print_differential_prob_table(cipher.SBOX)

dc.perform_dc()
