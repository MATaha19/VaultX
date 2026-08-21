from database import SessionLocal
from models import User
from rsa_utils import generate_rsa_key_pair


def generate_missing_keys():
    db = SessionLocal()

    try:
        users = (
            db.query(User)
            .filter(
                (User.public_key == None)
                | (User.private_key == None)
            )
            .all()
        )

        if not users:
            print("All users already have RSA keys.")
            return

        for user in users:
            public_key, private_key = generate_rsa_key_pair()

            user.public_key = public_key
            user.private_key = private_key

            print(
                f"RSA keys generated for user: "
                f"{user.username}"
            )

        db.commit()

        print(
            f"Successfully generated keys for "
            f"{len(users)} user(s)."
        )

    finally:
        db.close()


if __name__ == "__main__":
    generate_missing_keys()