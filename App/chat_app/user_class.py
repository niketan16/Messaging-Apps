import re

regex = "^[a-z0-9]+[\\._]?[a-z0-9]+[@]\\w+[.]\\w{2,3}$"


class User:
    """User Class which contains the properties of our user"""

    def __init__(
        self,
        username: str,
        name: str,
        email: str,
        password: str,
        confirm_password: str,
    ):
        """Initialisation of class variables

        Args:
            username (str): User Handle of the User
            name (str): Name of the User
            email (str): Email of the user
            password (str): Password of the user
            confirm_password (str): Confirm Password of the user
        """
        try:
            if (
                username != ""
                and name != ""
                and email != ""
                and password != ""
                and confirm_password != ""
            ):
                self.username = username
                self.name = name
                self.email = email
                self.password = password
                self.confirm_password = confirm_password
        except TypeError:
            raise TypeError()

    def check_email(self) -> bool:
        """Validates the email of the User

        Returns:
            bool: Returns True if it matches all the requirements else returns
            False.
        """
        if re.search(regex, self.email):
            return True
        else:
            return False

    def check_password(self) -> bool:
        """Checks the password field

        Returns:
            bool: Returns True if it matches all the requirements else returns
            False.
        """
        if self.password == self.confirm_password:
            if re.fullmatch(r"[A-Za-z0-9@#$%^&+=]{8,}", self.password):
                return True
            else:
                return False
        else:
            return False
