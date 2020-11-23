# Генератор последовательностей шифрования
Этот репозиторий содержит код, позволяющий генерировать последовательность промежуточных результатов работы криптоалгоритмов.

# Использование генератора
Для работы с генератором требуется .NET Framework 4.5 и оболочка `powershell`. Загрузить последнюю версию оболочки можно [по этой ссылке][1].

После установки `powershell` загрузите архив с модулем генератора [по этой ссылке][2]. Распакуйте содержимое архива в директорию по вашему выбору.

Запустите PowerShell и импортируйте модуль `Cipher`:
```powershell
Import-Module <путь к директории с модулем>\Cipher.psd1
```

Теперь вам доступен для использования командлет `Invoke-CipherCollection`, а также его псевдоним `cipher.collect`. Получить справку по командлету можно следующим образом:
```powershell
Get-Help cipher.collect
```

## Примеры использования генератора

### Создание последовательности работы AES
Основной способ генерации последовательности шифрования с помощью AES следующий:

```powershell
cipher.collect -Algorithm AES -PlainText "input\input-1.bin" -OutputFolder "output\aes-256-cbc-1"
```

Этот командлет выполняет следующие действия:
1. Считывает последовательность байтов из файла `input\input-1.bin`.
1. Подготавливает алгоритм шифрования AES со следующими параметрами:
     - Размер ключа: 256 бит.
     - Режим работы: `CBC`.
1. Создает выходную директорию `output\aes-256-cbc-1`, если она не существует.
1. Генерирует случайным образом ключ и вектор инициализации и записывает их в файлы `aes-key.bin` и `aes-iv.bin` в выходном каталоге.
1. Применяет алгоритм зашифрования к открытому тексту. Размещает в директории следующие файлы:
  - `aes-0.bin` - файл с открытым текстом,
  - `aes-1.bin` - файл с открытым текстом, при необходимости дополненный блоком нулей (если дополнение не требуется, то этот файл полностью совпадает с открытым текстом),
  - `aes-2.bin` - файл с открытым текстом, дополненный до необходимой длины (если дополнение не требуется, этот файл также полностью совпадает с открытым текстом),
  - `aes-3.bin` - результат применения операции XOR к предыдущему файлу и зашифрованному предыдущему блоку/вектору инициализации (согласно режиму CBC)
  - `aes-4.bin` - результат операции AddRoundKey, примененной к блокам предыдущего файла.
  - `aes-5.bin`, .. `aes-17.bin` - результаты раундов шифрования с 1 по 13 (реализованных предпросмотром по T-таблице), последовательно примененных к блокам предыдущего файла.
  - `aes-18.bin` - результат финального раунда шифрования (реализованного предпросмотром по TF-таблице). Этот файл  является шифротекстом (т.е. результатом работы криптоалгоритма).

**Примечание**: пока AES - это единственный поддерживаемый криптоалгоритм (реализация на основе класса [AesManaged][3]).

#### Другие способы задания открытого текста
Открытый текст можно задать напрямую в виде массива байтов. Пример запуска со случайным открытым текстом размером в 100 байт:
```powershell
$plainBytes = [byte[]]::new(100)
$random = [Random]::new()
$random.NextBytes($plainBytes)

cipher.collect -Algorithm AES -PlainText $plainBytes -OutputFolder "output\aes-256-cbc-2"
```

В качестве открытого текста можно указать строку. В таком случае последовательность байт будет получена из неё с помощью алгоритма кодирования UTF8:
```powershell
cipher.collect -Algorithm AES -PlainText "A plain text" -OutputFolder "output\aes-256-cbc-3"
```

Файл с исходным текстом можно указать, используя командлет `Get-Item` (`Get-ChildItem`). Так можно гаранитировать существование файла:
```powershell
$plainFile = Get-Item "input\input-1.bin"
cipher.collect -Algorithm AES -PlainText $plainFile -OutputFolder "output\aes-256-cbc-4"
```

#### Изменение параметров алгоритма
Для изменения доступны следующие параметры:
  - `-Mode` - режим работы алгоритма. Подерживаются режимы работы `CBC` (используется по-умолчанию) и `ECB`.
  - `-KeySize` - размер создаваемого ключа. Используется только если ключ не указан явно (в таком случае он будет создан случайным образом). Для AES допустимы три значения: 128, 192 и 256 (используется по-умолчанию)

Ниже показан пример запуска AES с длиной ключа 128 бит в режиме ECB:
```powershell
cipher.collect -Algorithm AES -PlainText "input\input-1.bin" -OutputFolder "output\aes-128-ecb-1" -Mode ECB -KeySize 128
```

**Примечание**: Параметр `-KeySize` влияет на число промежуточных результатов, т.к. от размера ключа зависит число раундов шифрования.

#### Использование существующего ключа
По-умолчанию генератор создает ключ и вектор инициализации случайным образом и сохраняет их в выходном каталоге. Может быть полезным использовать существующие ключ для нового запуска, например, чтобы сравнить работу алгоритма в разных режимах. Для этого следует воспользоваться параметрами `-Key` и `-InitializationVector`:
```powershell
$KeyPath = (Resolve-Path "output\aes-256-cbc-1\aes-key.bin").Path
$Key = [System.IO.File]::ReadAllBytes($KeyPath)
$IVPath = (Resolve-Path "output\aes-256-cbc-1\aes-iv.bin").Path
$IV = [System.IO.File]::ReadAllBytes($IVPath)
cipher.collect -Algorithm AES -PlainText "input\input-1.bin" -OutputFolder "output\aes-256-ecb-2" -Key $Key -InitializationVector $IV -Mode ECB
```

[1]:https://github.com/PowerShell/PowerShell/releases/latest
[2]:https://github.com/delatrie/cipher/releases/latest
[3]:https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.aesmanaged