from .main import verify_password, get_password_hash, upload_image, delete_image

def test_hash_verify_password():
    my_corr_pass = "password123"
    incorr_pass = "123password"
    my_pass_hash = get_password_hash(my_corr_pass)
    assert verify_password(my_corr_pass, my_pass_hash) == True
    assert verify_password(incorr_pass, my_pass_hash) == False

def test_upload_image():
    pass

def test_delete_image():
    pass