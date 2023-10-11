import rabin as rb

def read_file(filename: str) -> str:
    with open(filename, 'r') as file:
        result = file.readlines()
        file.close()

    return result

def write_file(filename: str, value):
    with open(filename, 'w') as file:
        if type(value) is list:
            if type(value[0]) is list:
                for v in value:
                    file.writelines(v)
        else:
            file.writelines(value)

        file.close()

def get_max(text: list) -> int:
    max_len = 0

    for temp in text:
        for t in temp:
            value = t.bit_length()
            if max_len < value:
                max_len = value

    return max_len 

def rabin_processing(input: str, output: str):
    input_text = read_file(f'{input}.txt')

    text = [
        [
            text[i:i+32] for i in range(0, len(text), 32)
        ] 
        for text in input_text]
    
    i_text = [
        [rb.text_to_int(t_iter) for t_iter in t]
            for t in text]
    
    max_bit_len = get_max(i_text)
    p, q = rb.get_keys(max_bit_len)
    n = p * q

    enc_int = [
        [
            f'{rb.encrypt_text(it, n)}\n' for it in temp
        ]
        for temp in i_text]

    output = f'enc-{output}.txt'
    write_file(output, enc_int)

    enc_int = read_file(output)
    enc_int = [int(elem) for elem in enc_int] 
    
    solutions = [rb.decrpyt_text(enc, p, q, n) for enc in enc_int]
    results  = [rb.find_correct_solution(sol) for sol in solutions]

    output_res = []
    for res in results:
        if res is not None:
            output_res.append(
                rb.int_to_text(res >> 8))

    write_file(output[4:], ''.join(output_res))

def main():
    rabin_processing('input', 'output')

if __name__ == '__main__':
    main()

