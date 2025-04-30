from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from PIL import Image
import io
import os

def encrypt_image(input_path, output_path, key):
    try:
        # Validate input file
        if not os.path.exists(input_path):
            raise FileNotFoundError(f"Input file not found: {input_path}")
        
        # Open and verify the image
        try:
            img = Image.open(input_path)
            img.verify()  # Verify the image integrity
            img = Image.open(input_path)  # Reopen as verify closes the file
        except Exception as e:
            raise ValueError(f"Invalid image file: {e}")

        # Convert image to byte data
        with io.BytesIO() as img_byte_arr:
            # Save in original format or default to PNG if format isn't available
            img_format = img.format if img.format else 'PNG'
            img.save(img_byte_arr, format=img_format)
            img_bytes = img_byte_arr.getvalue()

        # Generate random IV
        iv = get_random_bytes(AES.block_size)

        # Create cipher object
        cipher = AES.new(key, AES.MODE_CBC, iv)

        # Encrypt the data
        encrypted_bytes = cipher.encrypt(pad(img_bytes, AES.block_size))

        # Save encrypted data (IV + ciphertext)
        with open(output_path, 'wb') as f:
            f.write(iv)
            f.write(encrypted_bytes)
        
        print(f"Image successfully encrypted and saved to {output_path}")
        return True
    
    except Exception as e:
        print(f"Encryption failed: {str(e)}")
        return False

def decrypt_image(input_path, output_path, key):
    try:
        # Validate input file
        if not os.path.exists(input_path):
            raise FileNotFoundError(f"Input file not found: {input_path}")
        
        if os.path.getsize(input_path) <= AES.block_size:
            raise ValueError("File too small to contain valid encrypted data")

        # Read the encrypted file
        with open(input_path, 'rb') as f:
            iv = f.read(AES.block_size)
            encrypted_bytes = f.read()

        # Create cipher object
        cipher = AES.new(key, AES.MODE_CBC, iv)

        # Decrypt and unpad
        try:
            decrypted_bytes = unpad(cipher.decrypt(encrypted_bytes), AES.block_size)
        except ValueError as e:
            raise ValueError("Decryption failed - possibly incorrect key or corrupted data")

        # Convert back to image
        try:
            img = Image.open(io.BytesIO(decrypted_bytes))
            
            # Validate the image
            img.verify()
            img = Image.open(io.BytesIO(decrypted_bytes))
        except Exception as e:
            raise ValueError(f"Decrypted data is not a valid image: {e}")

        # Save the decrypted image
        img.save(output_path)
        print(f"Image successfully decrypted and saved to {output_path}")
        return True
    
    except Exception as e:
        print(f"Decryption failed: {str(e)}")
        return False

def get_key_input():
    while True:
        key_input = input("Enter your 16-byte key in hex (32 characters) or press Enter to generate one: ").strip()
        
        if not key_input:
            key = get_random_bytes(16)
            print(f"Generated new AES key: {key.hex()}")
            return key
        
        try:
            if len(key_input) != 32:
                raise ValueError("Key must be 32 hex characters (16 bytes)")
            key = bytes.fromhex(key_input)
            return key
        except ValueError as e:
            print(f"Invalid key: {e}. Please try again.")

def main():
    print("AES Image Encryption Tool")
    print("1. Encrypt Image")
    print("2. Decrypt Image")
    
    while True:
        choice = input("Enter your choice (1/2): ").strip()
        if choice in ['1', '2']:
            break
        print("Invalid choice. Please enter 1 or 2.")

    input_path = input("Enter input file path: ").strip()
    output_path = input("Enter output file path: ").strip()

    key = get_key_input()

    if choice == '1':
        success = encrypt_image(input_path, output_path, key)
    else:
        success = decrypt_image(input_path, output_path, key)

    if not success:
        print("Operation failed. See error messages above.")

if __name__ == "__main__":
    main()