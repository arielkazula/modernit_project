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
        while N < 10**digits and N > 10**(digits+1):
            p = number_theory_functions.generate_prime(digits//2 + 1)
            q = number_theory_functions.generate_prime(digits//2)
            N = (p-1)(q-1)

        gcd = -1
        e = 1
        while gcd != 1:
            x = randrange(0, 1)
            e = (N*x)//1
            gcd, a, b = number_theory_functions.extended_gcd(e, N)

        d = number_theory_functions.modular_inverse(e, N)
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
        return number_theory_functions.modular_exponent(m, self.private_key[1], self.private_key[0])

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
        return number_theory_functions.modular_exponent(c, self.private_key[1], self.private_key[0])
