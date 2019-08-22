import numpy as np
import pandas as pd
import os
import toycipher as tc

## 차분 분석에 사용하기 위한 입력-출력 테이블 출력
# @param sbox 입력-출력 테이블을 생성할 sbox
def print_inout_table(sbox):
    dim = len(sbox)
    np.set_printoptions(formatter={'int':hex})
    result = np.zeros(shape=(dim,dim))    

    for i in range(dim):
        for j in range(dim):
            result[i, j] = sbox[i] ^ sbox[j]            

    cols = []
    rows = []

    for i in range(dim):
        cols.append(str(i))
        rows.append(str(i))
    
    print("SBox: ", sbox)
    print()

    df = pd.DataFrame(result, index = rows, columns = cols, dtype=int)
    print("입력쌍-출력차분 테이블")
    print(df)
    print()

## 차분 분석에 사용하기 위한 차분분포표 출력
# @param sbox 차분 분포표를 만들 sbox
def print_differential_prob_table(sbox):
    dim = len(sbox)
    np.set_printoptions(formatter={'int':hex})    
    prob = np.zeros(shape=(dim,dim))

    for i in range(dim):
        for j in range(dim):            
            prob[i ^ j, sbox[i] ^ sbox[j]] += 1

    cols = []
    rows = []

    for i in range(dim):
        cols.append(str(i))
        rows.append(str(i))
    
    print("SBox: ", sbox)
    print()
    
    df = pd.DataFrame(prob, index = rows, columns = cols, dtype=int)
    print("입력차분-출력차분 빈도표")
    print(df)
    print()

## 암호 오라클
# @return 주어진 평문에 대해 암호문을 생성하는 블록 암호 객체, 라운드키는 랜덤하게 생성됨
def get_enc_oracle():
    cipher = tc.ToyCipher()
    cipher.rks = np.frombuffer(os.urandom(12), dtype=np.uint8).reshape(4, 3) & 0xf
    return cipher

## mask 위치에 차분이 존재하는지 확인
# @param mask 위치
# @param diff 차분
# @return True diff 차분에 mask 위치에 0이 아닌 차분이 존재하는 경우
# @return False 그 외
def filter(mask, diff):
    if ((mask & diff) > 0).any():
        return True

    return False

## 출력 차분 조건에 맞는 암호문쌍 생성
# @param cipher 분석하고자 하는 블록암호 객체
# @param input_diff 입력 차분
# @param mask 출력 차분이 존재해야 할 위치
# @param num_samples 암호문쌍을 생성하는데 사용할 평문쌍의 개수
# @return mask 위치에 차분이 존재하는 암호문쌍 목록
def generate_filtered_sample_pairs(cipher, input_diff, mask, num_samples):
    ct0 = []
    ct1 = []

    for i in range(num_samples):
        pt0 = np.frombuffer(os.urandom(3), dtype=np.uint8) & 0xf
        pt1 = pt0 ^ input_diff

        c0 = cipher.encrypt(pt0)
        c1 = cipher.encrypt(pt1)

        output_diff = c0 ^ c1
        
        if filter(mask, output_diff):
            ct0.append(c0)
            ct1.append(c1)

    return np.array(ct0), np.array(ct1)

## 키 복구 시도
# @param cipher 공격할 블록암호
# @param num_samples 공격에 필요한 평문쌍 수
# @param input_diff 입력 차분
# @param target_diff 대상 차분
# @param key_mask 복구하고자 하는 키의 위치
def try_recover_key(cipher, num_samples, input_diff, target_diff, key_mask):
    diff_mask = np.copy(target_diff)
    
    for i in range(len(diff_mask)):
        if diff_mask[i] > 0:
            diff_mask[i] = 0xf

    ct0, ct1 = generate_filtered_sample_pairs(cipher, input_diff, diff_mask, num_samples)

    num_filtered = len(ct0)

    key_mask = np.array(key_mask)
    count = np.zeros(shape=(16), dtype=int)

    for i in range(num_filtered):
        for k in range(16):
            dec0 = cipher.decrypt_last_round(ct0[i], key_mask & k)
            dec1 = cipher.decrypt_last_round(ct1[i], key_mask & k)

            if ((dec0 ^ dec1) == target_diff).all():
                count[k] += 1

    print("Key Count ", count)
    cand0 = np.argmax(count)
    count[cand0] = 0
    cand1 = np.argmax(count)
    
    print("Partial Key Candidates --> 1)", hex(cand0), "2)",  hex(cand1))
    print()

## 차분 분석 샘플 실행
#
def perform_dc():
    cipher = tc.ToyCipher()
    cipher.random_keys()    

    try_recover_key(cipher, 32, input_diff=(2, 0, 0), target_diff=(8, 0, 0), key_mask=(0xf, 0, 0))
    try_recover_key(cipher, 32, input_diff=(0, 2, 0), target_diff=(0, 0x4, 0), key_mask=(0, 0xf, 0))
    try_recover_key(cipher, 128, input_diff=(0, 0, 2), target_diff=(5, 0, 0xa), key_mask=(0, 0, 0xf))
    print("Real Key ", cipher.rks[3])
