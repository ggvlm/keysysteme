from sqlmodel import SQLModel, create_engine, Session

DATABASE_URL = "sqlite:///./keys.db"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
    echo=False,
)


def init_db() -> None:
    """Create all tables if they don't exist."""
    SQLModel.metadata.create_all(engine)


def get_session() -> Session:
    """Yield a database session."""
    with Session(engine) as session:
        yield session
