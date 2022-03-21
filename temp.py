import sys, os, argparse, hashlib, time, nmap

def main():
    parser = argparse.ArgumentParser(description='three-pronged hash cracking tool')

    parser.add_argument('--hashlist', dest='_hashlist',type=str, help='hash file path')
    parser.add_argument('--dict', dest='_dictionary', type=str, help ='dictionary file path')
    parser.add_argument('--type', dest='_hash_type',type=str, help='hash type (md5, sha1, sha256)')

    args = parser.parse_args()

    hashlist = args._hashlist
    dictionary = args._dictionary
    hash_type = str(args._hash_type).strip()
    

if __name__ == "__main__":
    main()
