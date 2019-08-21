import numpy as np
import pandas as pd
import os

class ToyCipher:

    SBOX = [0x6, 0x7, 0xb, 0xc, 0x9, 0x8, 0x4, 0x0, 0xe, 0x5, 0x3, 0xd, 0x1, 0x2, 0xf, 0xa]
    SINV = [0x7, 0xc, 0xd, 0xa, 0x6, 0x9, 0x0, 0x1, 0x5, 0x4, 0xf, 0x2, 0x3, 0xb, 0x8, 0xe]

    rks = []

    ## 랜덤 라운드 키 생성
    # @param self 객체 포인터
    def random_keys(self):
        self.rks = np.frombuffer(os.urandom(12), dtype=np.uint8).reshape(4, 3) & 0xf

    def substitute(self, sbox, nibbles):
        out = np.copy(nibbles)
        for i in range(3):
            out[i] = sbox[out[i]]

        return out

    ## 복호화에 사용되는 확산 연산
    # @param self 객체 포인터
    # @param nibbles 4비트 데이터 3개로 이루어진 배열
    # @return 확산이 적용된 4비트 데이터 3개로 이루어진 배열
    def permute_nibbles(self, nibbles):
        o0 =  (nibbles[0] & 0x8)       ^ ((nibbles[1] & 0x2) << 1) ^ ((nibbles[0] & 0x4) >> 1) ^  (nibbles[1] & 0x1)
        o1 = ((nibbles[0] & 0x2) << 2) ^ ((nibbles[2] & 0x8) >> 1) ^ ((nibbles[0] & 0x1) << 1) ^ ((nibbles[2] & 0x4) >> 2)
        o2 = ((nibbles[1] & 0x8))      ^ ((nibbles[2] & 0x2) << 1) ^ ((nibbles[1] & 0x4) >> 1) ^  (nibbles[2] & 0x1)

        return np.array([o0, o1, o2])

    ## 복호화에 사용되는 역 확산 연산
    # @param self 객체 포인터
    # @param nibbles 4비트 데이터 3개로 이루어진 배열
    # @return 확산이 적용된 4비트 데이터 3개로 이루어진 배열
    def inverse_permute_nibbles(self, nibbles):
        n0 = (nibbles[0] & 0x8) ^ ((nibbles[0] & 0x2) << 1) ^ ((nibbles[1] & 0x8) >> 2) ^ ((nibbles[1] & 0x2) >> 1)
        n1 = (nibbles[2] & 0x8) ^ ((nibbles[2] & 0x2) << 1) ^ ((nibbles[0] & 0x4) >> 1) ^  (nibbles[0] & 0x1)
        n2 = ((nibbles[1] & 0x4) << 1) ^ ((nibbles[1] & 0x1) << 2) ^ ((nibbles[2] & 0x4) >> 1) ^ (nibbles[2] & 0x1)

        return np.array([n0, n1, n2])

    ## 한 라운드 암호화
    # @param self 객체 포인터
    # @param block 암호화 할 블록
    # @param rk 라운드 키
    # @return 한 라운드 암호화된 한 블록 데이터
    def encrypt_one_round(self, block, rk):
        out = np.copy(block)
        out = self.substitute(self.SBOX, out)
        return self.permute_nibbles(out) ^ rk

    ## 한 라운드 복호화
    # @param self 객체 포인터
    # @param block 복호화 할 블록
    # @param rk 라운드 키
    # @return 한 라운드 복호화된 한 블록 데이터
    def decrypt_one_round(self, block, rk):
        out = self.inverse_permute_nibbles(np.array(block) ^ rk)        
        out = self.substitute(self.SINV, out)

        return out

    ## 마지막 라운드 암호화
    # @param self 객체 포인터
    # @param block 복호화 할 블록
    # @param rk 라운드 키
    # @return 마지막 한 라운드 복호화된 한 블록 데이터
    def encrypt_last_round(self, block, rk):
        enc = np.copy(block)        
        enc = self.substitute(self.SBOX, enc)
        
        return enc ^ rk

    ## 마지막 라운드 복호화
    # @param self 객체 포인터
    # @param block 복호화 할 블록
    # @param rk 라운드 키
    # @return 마지막 한 라운드 복호화된 한 블록 데이터
    def decrypt_last_round(self, block, rk):
        out = np.array(block) ^ rk
        out = self.substitute(self.SINV, out)

        return out

    ## 한 블록 암호화
    # @param self 객체 포인터
    # @param block 암호화 할 블록
    # @param rk 라운드 키 배열 (4 x 3 형태여야 함)
    # @return 암호문 한 블록
    def encrypt(self, block):
        enc = np.copy(block) ^ self.rks[0]
        
        for rk in self.rks[1:3]:
            enc = self.encrypt_one_round(enc, rk)

        return self.encrypt_last_round(enc, self.rks[3])

    ## 한 블록 복호화
    # @param self 객체 포인터
    # @param block 복호화 할 블록
    # @param rk 라운드 키 배열 (4 x 3 형태여야 함)
    # @return 평문 한 블록
    def decrypt(self, block):
        dec = self.decrypt_last_round(block, self.rks[3])

        for rk in reversed(self.rks[1:3]):
            dec = self.decrypt_one_round(dec, rk)

        return np.array(dec) ^ self.rks[0]
