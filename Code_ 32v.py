import random
from hashlib import sha256


# Функція для обчислення оберненого числа за модулем
def mod_inverse(a, m):
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        raise ValueError(f"Обернене число не існує для {a} за модулем {m}.")
    return x % m


# Розширений алгоритм Евкліда для знаходження НСД і коефіцієнтів
def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    g, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return g, x, y


# Генерація публічного ключа на основі приватного
def generate_public_key(p, g, private_key):
    return pow(g, private_key, p)


# Функція для підпису повідомлення
def sign_message(message, p, g, private_key):
    k = random.randint(1, p - 2)
    while extended_gcd(k, p - 1)[0] != 1:
        k = random.randint(1, p - 2)

    r = pow(g, k, p)
    m_hash = int(sha256(message.encode()).hexdigest(), 16)
    s = (m_hash - private_key * r) * mod_inverse(k, p - 1) % (p - 1)

    return (r, s)


# Функція для перевірки підпису
def verify_signature(message, r, s, p, g, public_key):
    if not (1 < r < p):
        return False

    m_hash = int(sha256(message.encode()).hexdigest(), 16)
    lhs = (pow(public_key, r, p) * pow(r, s, p)) % p
    rhs = pow(g, m_hash, p)

    # Діагностичне виведення для перевірки правильності обчислень
    print(f"Public key: {public_key}, r: {r}, s: {s}, m_hash: {m_hash}")
    print(f"LHS: {lhs}, RHS: {rhs}")

    return lhs == rhs


# Перевірка відповідності публічного та приватного ключів
def check_keys_match(private_key, public_key, p, g):
    calculated_public_key = generate_public_key(p, g, private_key)
    return calculated_public_key == public_key

# Основна частина програми
p = 467
g = 2

# Введення приватного та публічного ключів користувачем
private_key = int(input("Введіть приватний ключ: "))
public_key = int(input("Введіть публічний ключ: "))

# Перевірка, чи відповідають ключі
if check_keys_match(private_key, public_key, p, g):
    print("Ключі збігаються. Можна перевірити підпис.")

    message = "Hello, world!"  # Повідомлення для підпису
    r, s = sign_message(message, p, g, private_key)
    print(f"Підпис: (r={r}, s={s})")

    # Перевірка дійсності підпису
    is_valid = verify_signature(message, r, s, p, g, public_key)
    print(f"Підпис дійсний: {is_valid}")
else:
    print("Ключі не збігаються! Перевірка підпису неможлива.")
