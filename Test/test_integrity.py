from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from database import get_db, init_db, IOC, Source, Alert, Base, engine
from crud import create_ioc, create_source, create_alert
from schemas import IOCCreate, AlertCreate, SourceCreate
from datetime import datetime, timezone


def test_transaction_rollback():
    """Test that failed transactions are properly rolled back"""
    db = next(get_db())

    print("=" * 50)
    print("Day 28: ACID Transaction Test")
    print("=" * 50)

    # Count before
    count_before = db.query(IOC).count()
    print(f"\nIOC count before: {count_before}")

    try:
        # Start transaction
        ioc1 = IOC(value="10.0.0.1", type="ipv4")
        db.add(ioc1)

        ioc2 = IOC(value="10.0.0.2", type="ipv4")
        db.add(ioc2)

        # Force an error (duplicate unique constraint)
        source = Source(name="test", description="test")
        db.add(source)
        db.commit()

        # Try to insert duplicate source (will fail)
        source2 = Source(name="test", description="duplicate")
        db.add(source2)
        db.commit()  # This should raise an IntegrityError

    except IntegrityError as e:
        db.rollback()
        print(f"\n❌ IntegrityError caught")
        print("✅ Transaction rolled back")

    # Verify count unchanged
    count_after = db.query(IOC).count()
    print(f"\nIOC count after: {count_after}")
    print(f"Rollback verified: {count_before == count_after}")

    return count_before == count_after


def test_manual_rollback():
    """Test manual rollback."""
    db = next(get_db())

    print("\n--- Manual Rollback Test ---")

    count_before = db.query(IOC).count()

    # Insert within transaction
    ioc = IOC(value="99.99.99.99", type="ipv4")
    db.add(ioc)

    # Check it's in session but not committed
    print(
        f"In session (uncommitted): {db.query(IOC).filter(IOC.value == '99.99.99.99').first() is not None}"
    )

    # Rollback
    db.rollback()

    # Verify not in database
    result = db.query(IOC).filter(IOC.value == "99.99.99.99").first()
    print(f"After rollback: {result is None}")

    count_after = db.query(IOC).count()
    print(f"Count unchanged: {count_before == count_after}")

    return result is None and count_before == count_after


def test_foreign_key_constraint():
    """Test foreign key constraint enforcement"""
    db = next(get_db())

    print("\n--- Foreign Key Constraint Test ---")

    try:
        # Try to create alert with nonexistent ioc_id
        invalid_alert = Alert(
            ioc_id=99999,
            source_id=1,
            risk_level="HIGH",
            risk_score=100.0,
        )
        db.add(invalid_alert)
        db.commit()
        print("❌ Should have failed!")
        return False

    except SQLAlchemyError as e:
        db.rollback()
        print(f"✅ Foreign key error caught: {str(e)[:80]}...")
        return True


if __name__ == "__main__":
    init_db()

    test1 = test_transaction_rollback()
    test2 = test_manual_rollback()
    test3 = test_foreign_key_constraint()

    print("\n" + "=" * 50)
    print("Day 28 Results:")
    print(f"Transaction rollback: {'PASS' if test1 else 'FAIL'}")
    print(f"Manual rollback: {'PASS' if test2 else 'FAIL'}")
    print(f"Foreign key constraint: {'PASS' if test3 else 'FAIL'}")
    print("=" * 50)
