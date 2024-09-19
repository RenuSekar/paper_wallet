import hashlib
import ecdsa
import os
import qrcode
import base58
from reportlab.pdfgen import canvas

# Generate Private Key
def generate_private_key():
    private_key = os.urandom(32)  # Generate a 256-bit private key
    return private_key.hex()

# Convert Private Key to Public Key
def private_to_public_key(private_key_hex):
    private_key_bytes = bytes.fromhex(private_key_hex)
    sk = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    public_key = b'\x04' + vk.to_string()  # Uncompressed public key
    return public_key.hex()

# Convert Public Key to Bitcoin Address
def public_key_to_address(public_key_hex):
    public_key_bytes = bytes.fromhex(public_key_hex)
    sha256_pub_key = hashlib.sha256(public_key_bytes).digest()
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256_pub_key)
    ripemd160_pub_key = ripemd160.digest()

    # Add version byte (0x00 for Bitcoin mainnet)
    versioned_payload = b'\x00' + ripemd160_pub_key

    # Perform double SHA-256 for checksum
    checksum = hashlib.sha256(hashlib.sha256(versioned_payload).digest()).digest()[:4]

    # Append checksum
    address_bytes = versioned_payload + checksum

    # Encode using Base58
    address = base58.b58encode(address_bytes).decode('utf-8')
    return address

# Generate QR Code for the given data
def generate_qr_code(data, filename):
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill='black', back_color='white')
    img.save(f'{filename}.png')  # Save QR code as an image file

# Export keys to text file
def export_keys_to_file(private_key, public_key):
    with open("keys.txt", "w") as file:
        file.write(f"Private Key: {private_key}\n")
        file.write(f"Public Key (Bitcoin Address): {public_key}\n")

# Export keys and QR codes to a PDF document
def export_keys_to_pdf(private_key, public_key, private_key_qr, public_key_qr):
    c = canvas.Canvas("paper_wallet.pdf")
    
    # Add private key and public key as text
    c.drawString(100, 800, f"Private Key: {private_key}")
    c.drawString(100, 750, f"Public Key (Bitcoin Address): {public_key}")
    
    # Add QR code images to the PDF
    c.drawImage(private_key_qr, 100, 600, width=200, height=200)
    c.drawImage(public_key_qr, 100, 350, width=200, height=200)
    
    # Save the PDF
    c.save()

# Main function to generate keys, QR codes, and export them
def main():
    # Generate private and public keys
    private_key = generate_private_key()
    public_key = private_to_public_key(private_key)
    bitcoin_address = public_key_to_address(public_key)
    
    # Display the keys in the console
    print(f"Private Key: {private_key}")
    print(f"Public Key (Bitcoin Address): {bitcoin_address}")
    
    # Generate QR codes for both keys
    generate_qr_code(private_key, "private_key")
    generate_qr_code(bitcoin_address, "public_key")
    
    # Export the keys to a text file
    export_keys_to_file(private_key, bitcoin_address)
    
    # Export the keys and QR codes to a PDF
    export_keys_to_pdf(private_key, bitcoin_address, "private_key.png", "public_key.png")

if __name__ == "__main__":
    main()
