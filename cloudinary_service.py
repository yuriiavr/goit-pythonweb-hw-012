import os
import cloudinary
import cloudinary.uploader

cloudinary.config(
    cloud_name=os.environ.get("CLOUDINARY_NAME"),
    api_key=os.environ.get("CLOUDINARY_API_KEY"),
    api_secret=os.environ.get("CLOUDINARY_API_SECRET"),
    secure=True
)

def upload_avatar(file_content, public_id: str):
    r = cloudinary.uploader.upload(
        file_content,
        public_id={"public_id": public_id, "overwrite": True},
        folder="ContactApp/Avatars"
    )
    return r['secure_url']