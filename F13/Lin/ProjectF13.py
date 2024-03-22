using secp256k1;
using System;
using System.Diagnostics;
using System.Security.Cryptography;

namespace BitcoinKeyGeneration
{
    internal class Program
    {
        static void Main(string[] args)
        {
            // Диапазон бит для генерации ключей
            int bitRange = 66;

            // Префикс адреса
            string addressPrefix = "13zb1";

            // Создание объекта для измерения времени выполнения
            Stopwatch stopwatch = new Stopwatch();

            // Создание объекта библиотеки secp256k1
            secp256k1.secp256k1 keyGenerator = new secp256k1.secp256k1();
            keyGenerator.InitSecp256Lib();

            // Переменная для хранения сгенерированного закрытого ключа
            byte[] privateKeyBytes;

            // Переменная для хранения адреса
            string address;

            // Генерация ключей, пока не будет найден ключ, подходящий под условия
            do
            {
                // Генерация случайного закрытого ключа
                privateKeyBytes = GenerateRandomPrivateKey();

                // Преобразование закрытого ключа в адрес
                address = keyGenerator.PrivateKeyToBitcoinAddress(BytesToHexString(privateKeyBytes));

            } while (!IsWithinBitRange(privateKeyBytes, bitRange) || !address.StartsWith(addressPrefix));

            // Вывод результатов
            Console.WriteLine($"Сгенерированный закрытый ключ: {BytesToHexString(privateKeyBytes)}");
            Console.WriteLine($"Соответствующий адрес: {address}");

            // Остановка счетчика времени
            stopwatch.Stop();
            long elapsedMilliseconds = stopwatch.ElapsedMilliseconds;
            Console.WriteLine($"Завершено за {elapsedMilliseconds} миллисекунд.");
        }

        // Метод для генерации случайного закрытого ключа
        static byte[] GenerateRandomPrivateKey()
        {
            byte[] privateKey = new byte[32];
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(privateKey);
            }
            return privateKey;
        }

        // Метод для преобразования массива байт в строку в шестнадцатеричном формате
        static string BytesToHexString(byte[] byteArray)
        {
            string hexString = "";
            foreach (byte b in byteArray)
            {
                hexString += b.ToString("X2").ToLowerInvariant();
            }
            return hexString;
        }

        // Метод для проверки, находится ли закрытый ключ в заданном диапазоне бит
        static bool IsWithinBitRange(byte[] privateKeyBytes, int bitRange)
        {
            // Вычисление количества бит в закрытом ключе
            int bitCount = privateKeyBytes.Length * 8;

            // Проверка, находится ли количество бит в допустимом диапазоне
            return bitCount == bitRange;
        }
    }
}
