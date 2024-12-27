import base64
import os
import pyotp
from PIL import Image
from proto import migration_pb2
from pyzbar.pyzbar import decode
from urllib.parse import unquote


def list_png_files(folder_path):
    """List all files in the folder and filter for .png files

    Args:
        Path where png files are kept

    Returns:
        A list of png files
    """
    return [file for file in os.listdir(folder_path) if file.endswith(".png")]


def decode_qr_code(image_path):
    """Decodes a QR code from an image file.

    Args:
        image_path: The path to the QR code image file (e.g., 'qr_code.png').

    Returns:
        A list of decoded data objects, or None if no QR code was found.
    """
    try:
        image = Image.open(image_path)
        decoded_data = decode(image)
        return decoded_data
    except Exception as e:
        print(f"Error decoding QR code: {e}")
        return None


def add_base64_padding(b64_string):
    """Adds padding characters to base64 encoded string if needed.

    Args:
        b64_string: base64 string that may or may not be padded

    Returns:
        The string with proper padding

    """
    missing_padding = len(b64_string) % 4
    if missing_padding:
        b64_string += "=" * (4 - missing_padding)
    return b64_string


def parse_migration_data(base64_data, png):
    """Parses base64-encoded migration data after ensuring it is properly padded,
       and upon failure, it reattempts but without padding and without
       validation.

    Args:
        base64_data: Base64 encoded data

    Returns:
        A parsed migration record, or None on failure.
    """
    try:
        url_decoded_b64 = unquote(base64_data)

        try:
            #  Attempting to decode after adding a bit of padding
            padded_b64 = add_base64_padding(url_decoded_b64)
            decoded_bytes = base64.b64decode(padded_b64, validate=True)
            migration_payload = migration_pb2.MigrationPayload()
            migration_payload.ParseFromString(decoded_bytes)
            return migration_payload
        except Exception as e_inner:
            print(f"Base64 decoding failed with padding: {e_inner}")

            try:
                decoded_bytes = base64.b64decode(url_decoded_b64, validate=False)
                migration_payload = migration_pb2.MigrationPayload()
                migration_payload.ParseFromString(decoded_bytes)
                return migration_payload
            except Exception as e_relaxed:
                print(
                    f"Base64 decoding failed without padding and with relaxed validation: {e_relaxed}"
                )
                return None

    except Exception as e:
        print(f"Error parsing protobuf data: {e}")
        return None


def get_digits_value(digits_enum):
    """Converts the Digits enum to its corresponding integer value"""
    if digits_enum == migration_pb2.Digits.DIGITS_SIX:
        return 6
    elif digits_enum == migration_pb2.Digits.DIGITS_EIGHT:
        return 8
    else:
        return 6  # we will default to 6


def generate_token(record):
    """Generates a token (TOTP or HOTP) based on the migration record."""
    try:
        secret = base64.b32encode(record.secret).decode("utf-8")
        digits = get_digits_value(record.digits)

        if record.otptype == "HOTP":
            hotp = pyotp.HOTP(secret)
            token = hotp.at(record.counter)
            return token, "HOTP", record.counter

        else:  # TOTP
            totp = pyotp.TOTP(secret, digits=digits)
            token = totp.now()
            return token, "TOTP", None
    except Exception as e:
        print(f"Error generating token: {e}")
        return None, None, None


if __name__ == "__main__":

    qr_code_path = "qr_codes"
    qr_png_files = list_png_files(qr_code_path)

    for png in qr_png_files:
        image_file = qr_code_path + "/" + png
        decoded_results = decode_qr_code(image_file)

        if decoded_results:
            for result in decoded_results:
                if result.data.decode("utf-8").startswith(
                    "otpauth-migration://offline?data="
                ):
                    uri = result.data.decode("utf-8")
                    base64_data = uri.split("?data=")[1]
                    migration_payload = parse_migration_data(base64_data, png)

                    if migration_payload:

                        for record in migration_payload.otp_parameters:
                            print("Record found:")
                            # print(f"  Secret (base64): {base64.b64encode(record.secret).decode('utf-8')}")
                            print(f"  Name: {record.name}")
                            print(f"  Issuer: {record.issuer}")
                            print(f"  Algorithm: {record.algorithm}")
                            print(f"  Digits: {get_digits_value(record.digits)}")
                            print(f"  Type: {record.type}")
                            if record.otptype == "HOTP":
                                print(f"    Counter: {record.counter}")

                            token, token_type, counter = generate_token(record)
                            if token:
                                if token_type == "HOTP":
                                    print(
                                        f"    Current {token_type} Token: {token} at counter: {counter}"
                                    )
                                else:
                                    print(
                                        f"    {record.issuer} {record.name} Token: {token}"
                                    )

                            print("")

                    else:
                        print("Error parsing base64 data.")
                else:
                    print(f"Unusable.  {png} decode must include string \"otpauth-migration://offline?data=\":")
                    print(f"Type: {result.type}")
                    print(f"Contained Data: {result.data.decode('utf-8')}")
                    print(f"Bounding Box: {result.rect}")
        else:
            print("No QR code found in the image or decoding failed.")
