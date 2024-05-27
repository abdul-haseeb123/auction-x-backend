# Auction X Backend

This project is an ecommerce app where users can list their products, which will then be auctioned.

## Features

- User registration and authentication
- Product listing and auction functionality
- Bidding on products
- Automatic bidding system
- Notifications for auction updates
- User profile management
- Search functionality for products
- Admin panel for managing users and products
- Payment integration for successful auctions
- Transaction history tracking

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/abdul-haseeb123/auction-x-backend
   ```

2. Create a virtual environment:

   ```bash
   python -m venv venv
   ```

3. Activate the virtual environment:

   - For Windows:

     ```bash
     venv\Scripts\activate
     ```

   - For macOS/Linux:

     ```bash
     source venv/bin/activate
     ```

4. Install the required dependencies:

   ```bash
   pip install -r requirements.txt
   ```

## Usage

To run the server, execute the following command:

```bash
uvicorn backend.main:app --reload --host=localhost
```
