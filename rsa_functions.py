import number_theory_functions
from random import randrange


class RSA():
    def __init__(self, public_key, private_key=None):
        self.public_key = public_key
        self.private_key = private_key

    @staticmethod
    def generate(digits=10):
        """
        Creates an RSA encryption system object

        Parameters
        ----------
        digits : The number of digits N should have

        Returns
        -------
        RSA: The RSA system containing:
        * The public key (N,e)
        * The private key (N,d)
        """

        # generate p,q
        N = -1
        while N < 10**digits or N > 10**(digits+1):
            p = number_theory_functions.generate_prime(digits//2 + 1)
            q = number_theory_functions.generate_prime(digits//2)
            if p is None or q is None:
                continue
            N = p*q

        phi = (p-1)*(q-1)
        gcd = -1
        e = 1
        while gcd != 1:
            e = randrange(1, phi)
            gcd, a, b = number_theory_functions.extended_gcd(e, phi)

        d = number_theory_functions.modular_inverse(e, phi)

        return RSA((N, e), (N, d))

    def encrypt(self, m):
        """
        Encrypts the plaintext m using the RSA system

        Parameters
        ----------
        m : The plaintext to encrypt

        Returns
        -------
        c : The encrypted ciphertext
        """
        if m is None:
            return None
        gcd, a, b = number_theory_functions.extended_gcd(self.private_key[0], m)
        if gcd != 1:
            return None

        return number_theory_functions.modular_exponent(m, self.public_key[1], self.private_key[0])

    def decrypt(self, c):
        """
        Decrypts the ciphertext c using the RSA system

        Parameters
        ----------
        c : The ciphertext to decrypt

        Returns
        -------
        m : The decrypted plaintext
       """
        if c is None:
            return None
        return number_theory_functions.modular_exponent(c, self.private_key[1], self.private_key[0])
