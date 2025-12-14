import os
import sys

sys.path.insert(0, os.path.abspath('..'))

autodoc_mock_imports = [
    "fastapi", "sqlalchemy", "redis", "asyncio", 
    "pydantic", "passlib", "jose", "python_multipart", 
    "fastapi_limiter", "cloudinary", "database", 
    "email_service", "cloudinary_service",
    "auth"
]

project = 'Contacts REST API'
copyright = '2025, Contacts Team'
author = 'Contacts Team'
release = '1.0.2'

extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.napoleon',
    'sphinx.ext.coverage',
    'sphinx.ext.viewcode',
    'sphinx.ext.todo',
]

templates_path = ['_templates']
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']
html_theme = 'furo'
html_static_path = ['_static']

autodoc_default_options = {
    'members': True,
    'member-order': 'bysource',
    'undoc-members': False,
    'exclude-members': '__weakref__',
    'show-inheritance': True,
}