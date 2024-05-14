import hashlib

def generate_hash(data):
    # MD5 hash
    md5_hash = hashlib.md5(data.encode()).hexdigest()
    print("MD5 hash:", md5_hash)

    # SHA-1 hash
    sha1_hash = hashlib.sha1(data.encode()).hexdigest()
    print("SHA-1 hash:", sha1_hash)

    # SHA-224 hash
    sha224_hash = hashlib.sha224(data.encode()).hexdigest()
    print("SHA-224 hash:", sha224_hash)

    # SHA-256 hash
    sha256_hash = hashlib.sha256(data.encode()).hexdigest()
    print("SHA-256 hash:", sha256_hash)

    # SHA-384 hash
    sha384_hash = hashlib.sha384(data.encode()).hexdigest()
    print("SHA-384 hash:", sha384_hash)

    # SHA-512 hash
    sha512_hash = hashlib.sha512(data.encode()).hexdigest()
    print("SHA-512 hash:", sha512_hash)

if __name__ == "__main__":
    data = input("Enter the text to generate hash: ")
    generate_hash(data)

    # Keep the program open
    input("Press Enter to exit...")
