import os
import cloudinary
import cloudinary.uploader
from typing import BinaryIO

cloudinary.config(
    cloud_name=os.environ.get("CLOUDINARY_NAME", "your_cloud_name"),
    api_key=os.environ.get("CLOUDINARY_API_KEY", "your_api_key"),
    api_secret=os.environ.get("CLOUDINARY_API_SECRET", "your_api_secret"),
    secure=True
)

def upload_avatar(file_content: BinaryIO, public_id: str):
    r = cloudinary.uploader.upload(
        file_content,
        public_id={"public_id": public_id, "overwrite": True},
        folder="ContactApp/Avatars"
    )
    return r['secure_url']