import pytest_asyncio
import pytest
import backend.db.listings as listings
from ..schemas.images import Image

_user_inserted = False


@pytest.fixture(name="example_image")
def get_example_image():
    return Image(
        asset_id="example_asset_id",
        public_id="example_public_id",
        width=800,
        height=600,
        resource_type="image",
        tags=[],
        url="http://example.com/image.jpg",
        secure_url="https://example.com/image.jpg",
    ).model_dump()


@pytest.fixture(name="example_listing")
def get_example_listing(example_image):
    return {
        "title": "Example Listing",
        "description": "This is an example listing for testing purposes.",
        "slug": "example-listing-12345678",
        "active": True,
        "closing_date": "2026-12-31T23:59:59",
        "category": "Electronics",
        "bids": [],
        "starting_bid": 10.0,
        "current_bid": 10.0,
        "winner": None,
        "cover_image": example_image,
        "images": [example_image],
    }


@pytest_asyncio.fixture
async def test_user(test_db):
    global _user_inserted
    user_data = {
        "full_name": "Test User 1",
        "username": "testuser1",
        "email": "testuser1@example.com",
        "password": "testpassword1",
        "account_type": "EMAIL",
    }

    if not _user_inserted:
        existing = await test_db.users.find_one({"username": user_data["username"]})
        if not existing:
            await test_db.users.insert_one(user_data)
        _user_inserted = True

    return user_data


@pytest.mark.asyncio
async def test_create_listing(test_user, example_listing, test_db):
    example_listing["owner"] = "not_a_real_user"
    with pytest.raises(ValueError, match="owner does not exist"):
        await listings.create_listing(example_listing, test_db)

    example_listing["owner"] = test_user["username"]
    inserted_id = await listings.create_listing(example_listing, test_db)
    assert inserted_id is not None, "Listing should be created successfully"

    listing = await test_db.listings.find_one(
        {"owner": test_user["username"], "slug": example_listing["slug"]}
    )

    assert listing is not None, "Listing should be found in the database"
    assert listing["title"] == example_listing["title"], "Listing title should match"
    assert listing["description"] == example_listing["description"], (
        "Listing description should match"
    )
    assert listing["owner"] == test_user["username"], "Listing owner should match"
    assert listing["cover_image"] is not None, "Listing should have a cover image"
    assert len(listing["images"]) == len(example_listing["images"]), (
        "Listing images should match"
    )
    assert listing["active"] is True, "Listing should be active"
    assert listing["starting_bid"] == example_listing["starting_bid"], (
        "Listing starting bid should match"
    )
    assert listing["current_bid"] == example_listing["starting_bid"], (
        "Listing current bid should match starting bid"
    )

    await test_db.listings.delete_one({"slug": listing["slug"]})
    await test_db.users.update_one(
        {"username": test_user["username"]}, {"$pull": {"listings": listing["_id"]}}
    )


@pytest.mark.asyncio
async def test_get_listings(test_user, example_listing, test_db):
    example_listing["owner"] = test_user["username"]
    await listings.create_listing(example_listing, test_db)

    listings_list = await listings.get_listings(test_db)
    assert len(listings_list) > 0, (
        "There should be at least one listing in the database"
    )

    found_listing = next(
        (
            listing
            for listing in listings_list
            if listing["owner"] == test_user["username"]
        ),
        None,
    )
    assert found_listing is not None, (
        "Listing created by test user should be found in the listings list"
    )
    assert found_listing["title"] == example_listing["title"], (
        "Listing title should match"
    )

    await test_db.listings.delete_one({"slug": found_listing["slug"]})
    await test_db.users.update_one(
        {"username": test_user["username"]},
        {"$pull": {"listings": found_listing["_id"]}},
    )


@pytest.mark.asyncio
async def test_get_listing_by_slug(test_user, example_listing, test_db):
    example_listing["owner"] = test_user["username"]
    listing = await test_db.listings.insert_one(example_listing)
    await test_db.users.update_one(
        {"username": test_user["username"]},
        {"$push": {"listings": listing.inserted_id}},
    )

    found_listing = await listings.get_listing_by_slug(example_listing["slug"], test_db)
    assert found_listing is not None, "Listing should be found by slug"
    assert found_listing["slug"] == example_listing["slug"], "Listing slug should match"
    assert found_listing["owner"] == test_user["username"], "Listing owner should match"
    assert found_listing["title"] == example_listing["title"], (
        "Listing title should match"
    )
    assert found_listing["description"] == example_listing["description"], (
        "Listing description should match"
    )
    assert found_listing["cover_image"] is not None, "Listing should have a cover image"
    assert len(found_listing["images"]) == len(example_listing["images"]), (
        "Listing images should match"
    )
    assert found_listing["active"] is True, "Listing should be active"

    await test_db.listings.delete_one({"slug": found_listing["slug"]})
    await test_db.users.update_one(
        {"username": test_user["username"]},
        {"$pull": {"listings": found_listing["_id"]}},
    )


@pytest.mark.asyncio
async def test_update_listing(test_user, example_listing, test_db):
    example_listing["owner"] = test_user["username"]
    listing = await test_db.listings.insert_one(example_listing)

    updated_data = {
        "title": "Updated Listing Title",
        "description": "This is an updated description for the listing.",
        "active": False,
    }

    updated_listing = await listings.update_listing(
        example_listing["slug"], updated_data, test_db, new=True
    )

    assert updated_listing is not None, "Listing should be updated successfully"
    assert updated_listing["title"] == updated_data["title"], (
        "Listing title should be updated"
    )
    assert updated_listing["description"] == updated_data["description"], (
        "Listing description should be updated"
    )
    assert updated_listing["active"] is False, "Listing should be inactive after update"

    await test_db.listings.delete_one({"_id": listing.inserted_id})
    await test_db.users.update_one(
        {"username": test_user["username"]},
        {"$pull": {"listings": listing.inserted_id}},
    )


@pytest.mark.asyncio
async def test_update_listing_bid(test_user, example_listing, test_db):
    example_listing["owner"] = test_user["username"]
    listing = await test_db.listings.insert_one(example_listing)

    bid_data = {
        "bidder": test_user["username"],
        "amount": 15.0,
        "created_at": "2023-10-01T12:00:00Z",
    }

    updated_listing = await listings.update_listing_bid(
        example_listing["slug"], bid_data, test_db, new=True
    )

    assert updated_listing is not None, "Listing should be updated with new bid"
    assert len(updated_listing["bids"]) == 1, "There should be one bid in the listing"
    assert updated_listing["current_bid"] == bid_data["amount"], (
        "Current bid should match the new bid amount"
    )

    await test_db.listings.delete_one({"_id": listing.inserted_id})
    await test_db.users.update_one(
        {"username": test_user["username"]},
        {"$pull": {"listings": listing.inserted_id}},
    )


@pytest.mark.asyncio
async def test_delete_listing(test_user, example_listing, test_db):
    example_listing["owner"] = test_user["username"]
    listing = await test_db.listings.insert_one(example_listing)

    deleted_count = await listings.delete_listing(
        test_user["username"], example_listing["slug"], test_db
    )

    assert deleted_count.deleted_count == 1, "One listing should be deleted"

    # Verify that the listing is no longer in the database
    found_listing = await test_db.listings.find_one({"_id": listing.inserted_id})
    assert found_listing is None, "Listing should not be found after deletion"

    # Verify that the listing was removed from the user's listings
    user = await test_db.users.find_one({"username": test_user["username"]})
    assert listing.inserted_id not in user["listings"], (
        "Listing ID should be removed from user's listings"
    )
    await test_db.users.delete_one({"username": test_user["username"]})
