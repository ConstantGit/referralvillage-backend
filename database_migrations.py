# alembic.ini
# A generic, single database configuration.

[alembic]
# path to migration scripts
script_location = alembic

# template used to generate migration file names; The default value is %%(rev)s_%%(slug)s
# Uncomment the line below if you want the files to be prepended with date and time
file_template = %%(year)d%%(month).2d%%(day).2d_%%(hour).2d%%(minute).2d-%%(rev)s_%%(slug)s

# sys.path path, will be prepended to sys.path if present.
# defaults to the current working directory.
prepend_sys_path = .

# timezone to use when rendering the date within the migration file
# as well as the filename.
# If specified, requires the python-dateutil library
# one of: postgresql(+psycopg2/3/pg8000), mysql(+mysqlclient/pymysql/mysqlconnector/...),
# mssql(+pyodbc), sqlite
# examples: postgresql+psycopg2://user:password@localhost/dbname
#           sqlite:///path/to/file.db
sqlalchemy.url = 

# set to 'true' to run the environment during
# the 'revision' command, regardless of autogenerate
# revision_environment = false

# set to 'true' to allow .pyc and .pyo files without
# a source .py file to be detected as revisions in the
# versions/ directory
# sourceless = false

# version location specification; This defaults
# to alembic/versions.  When using multiple version
# directories, initial revisions must be specified with --version-path.
# The path separator used here should be the separator specified by "version_path_separator" below.
# version_locations = %(here)s/bar:%(here)s/bat:alembic/versions

# version path separator; As mentioned above, this is the character used to split
# version_locations. The default within new alembic.ini files is "os", which uses os.pathsep.
# If this key is omitted entirely, it falls back to the legacy behavior of splitting on spaces and/or commas.
# Valid values for version_path_separator are:
#
# version_path_separator = :
# version_path_separator = ;
# version_path_separator = space
version_path_separator = os  # Use os.pathsep.
# the output encoding used when revision files
# are written from script.py.mako
# output_encoding = utf-8

[post_write_hooks]
# post_write_hooks defines scripts or Python functions that are run
# on newly generated revision scripts.  See the documentation for further
# detail and examples

# format using "black" - use the console_scripts runner, against the "black" entrypoint
# hooks = black
# black.type = console_scripts
# black.entrypoint = black
# black.options = -l 79 REVISION_SCRIPT_FILENAME

# Logging configuration
[loggers]
keys = root,sqlalchemy,alembic

[handlers]
keys = console

[formatters]
keys = generic

[logger_root]
level = WARN
handlers = console
qualname =

[logger_sqlalchemy]
level = WARN
handlers =
qualname = sqlalchemy.engine

[logger_alembic]
level = INFO
handlers =
qualname = alembic

[handler_console]
class = StreamHandler
args = (sys.stderr,)
level = NOTSET
formatter = generic

[formatter_generic]
format = %(levelname)-5.5s [%(name)s] %(message)s
datefmt = %H:%M:%S

# alembic/env.py
from logging.config import fileConfig
from sqlalchemy import engine_from_config
from sqlalchemy import pool
from alembic import context
import os
import sys
from pathlib import Path

# Add project root to path
sys.path.append(str(Path(__file__).parent.parent))

from app.db.base import Base
from app.core.config import settings

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
# This line sets up loggers basically.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# add your model's MetaData object here
# for 'autogenerate' support
target_metadata = Base.metadata

# other values from the config, defined by the needs of env.py,
# can be acquired:
# my_important_option = config.get_main_option("my_important_option")
# ... etc.

def get_url():
    """Get database URL from environment or settings"""
    return os.getenv("DATABASE_URL", settings.DATABASE_URL)

def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode."""
    url = get_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()

def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""
    configuration = config.get_section(config.config_ini_section)
    configuration["sqlalchemy.url"] = get_url()
    
    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection, target_metadata=target_metadata
        )

        with context.begin_transaction():
            context.run_migrations()

if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()

# alembic/script.py.mako
"""${message}

Revision ID: ${up_revision}
Revises: ${down_revision | comma,n}
Create Date: ${create_date}

"""
from alembic import op
import sqlalchemy as sa
${imports if imports else ""}

# revision identifiers, used by Alembic.
revision = ${repr(up_revision)}
down_revision = ${repr(down_revision)}
branch_labels = ${repr(branch_labels)}
depends_on = ${repr(depends_on)}


def upgrade() -> None:
    ${upgrades if upgrades else "pass"}


def downgrade() -> None:
    ${downgrades if downgrades else "pass"}

# scripts/init_db.py
"""Initialize database with sample data"""
import asyncio
from sqlalchemy.orm import Session
from app.db.session import SessionLocal, engine
from app.db.base import Base
from app.models import User, Category, UserRole
from app.core.security import get_password_hash
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def init_db(db: Session) -> None:
    """Initialize database with base data"""
    
    # Create tables
    Base.metadata.create_all(bind=engine)
    logger.info("Database tables created")
    
    # Check if data already exists
    if db.query(User).first():
        logger.info("Database already initialized")
        return
    
    # Create admin user
    admin = User(
        email="admin@referralvillage.com",
        password_hash=get_password_hash("admin123"),
        first_name="Admin",
        last_name="User",
        role=UserRole.ADMIN,
        is_verified=True,
        is_active=True
    )
    db.add(admin)
    
    # Create sample categories
    categories = [
        {"name": "Home Services", "slug": "home-services", "icon": "🏠"},
        {"name": "Professional Services", "slug": "professional-services", "icon": "💼"},
        {"name": "Technology", "slug": "technology", "icon": "💻"},
        {"name": "Marketing", "slug": "marketing", "icon": "📱"},
        {"name": "Finance", "slug": "finance", "icon": "💰"},
        {"name": "Real Estate", "slug": "real-estate", "icon": "🏢"},
        {"name": "Healthcare", "slug": "healthcare", "icon": "🏥"},
        {"name": "Education", "slug": "education", "icon": "🎓"},
    ]
    
    for cat_data in categories:
        category = Category(**cat_data, is_active=True)
        db.add(category)
    
    db.commit()
    logger.info("Database initialized with sample data")

if __name__ == "__main__":
    db = SessionLocal()
    try:
        init_db(db)
    finally:
        db.close()

# scripts/migrate.sh
#!/bin/bash
# Database migration helper script

echo "ReferralVillage Database Migration Tool"
echo "======================================"

# Check if alembic is installed
if ! command -v alembic &> /dev/null; then
    echo "Alembic not found. Installing..."
    pip install alembic
fi

# Initialize alembic if not already done
if [ ! -d "alembic" ]; then
    echo "Initializing Alembic..."
    alembic init alembic
fi

case "$1" in
    "init")
        echo "Creating initial migration..."
        alembic revision --autogenerate -m "Initial migration"
        ;;
    "migrate")
        echo "Creating new migration: $2"
        alembic revision --autogenerate -m "$2"
        ;;
    "upgrade")
        echo "Upgrading database to latest..."
        alembic upgrade head
        ;;
    "downgrade")
        echo "Downgrading database..."
        alembic downgrade -1
        ;;
    "history")
        echo "Migration history:"
        alembic history
        ;;
    *)
        echo "Usage: ./migrate.sh [init|migrate|upgrade|downgrade|history]"
        echo "  init      - Create initial migration"
        echo "  migrate   - Create new migration with message"
        echo "  upgrade   - Apply all pending migrations"
        echo "  downgrade - Rollback last migration"
        echo "  history   - Show migration history"
        ;;
esac