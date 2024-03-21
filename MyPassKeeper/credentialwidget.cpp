#include "credentialwidget.h"
#include "ui_credentialwidget.h"

#include <openssl/evp.h>

#include <QBuffer>
#include <QCryptographicHash>
#include <QFile>
#include <QJsonDocument>
#include <QClipboard>
#include <QMessageBox>


credentialwidget::credentialwidget(QString site, QString login_encrypted, QString password_encrypted, QWidget *parent)
    :QWidget(parent)
    , ui(new Ui::credentialwidget)
{
    this->pass_encr = new char[password_encrypted.length()];
    QByteArray pass_ba = password_encrypted.toUtf8();
    strcpy(pass_encr, pass_ba.data());
    qDebug() << "***pass_encr" << pass_encr;

    this->log_encr = new char[login_encrypted.length()];
    QByteArray log_ba = login_encrypted.toUtf8();
    strcpy(log_encr, log_ba.data());
    qDebug() << "***log_encr" << log_encr;

    ui->setupUi(this);

    ui->lblSite->setText(site);
    ui->editLogin->setText("******");
    ui->editPassword->setText("******");
}

credentialwidget::~credentialwidget()
{
    delete [] pass_encr;
    delete ui;
}


// Функция считывает учётные записи из файла json в структуру данных Qlist
bool credentialwidget::checkJSON(QByteArray &aes256_key)
{

    qDebug() << "*** checkJSON arg = " << aes256_key;
    QFile jsonFile("D:/University/qt_projects/MyPassKeeper/json/cridentials_enc.json");

    // Проверка существования и доступности файла
    if (!jsonFile.exists()) {
        qDebug() << "File not found: cridentials_enc.json";
        return false;
    }

    if (!jsonFile.open(QFile::ReadOnly)) {
        qDebug() << "Failed to open file: cridentials_enc.json";
        return false;
    }

    QByteArray hexEncryptedBytes = jsonFile.readAll();
    // qDebug() << "*** hexEncryptedBytes orig" << hexEncryptedBytes;

    QByteArray encryptedBytes = QByteArray::fromHex(hexEncryptedBytes);
    // qDebug() << "*** hexEncryptedBytes" << encryptedBytes.toHex();

    QByteArray decryptedBytes;

    // Расшифровка зашифрованных данных с использованием ключа AES-256
    int ret_code = decrypter(aes256_key, encryptedBytes, decryptedBytes);
    qDebug() << "*** decrypter(), decryptedBytes = " << decryptedBytes.toHex() << "retCODE" << ret_code;

    QJsonParseError jsonErr;
    QJsonDocument jsonDoc = QJsonDocument::fromJson(decryptedBytes, &jsonErr);

    if (jsonErr.error != QJsonParseError::NoError)
        return false;

    jsonFile.close();

    return ret_code;
}

// key = b0c27fca74fa91934900c9ffcb3dcca5b807a3c059a3b516cdd0788807b5ff49
// iv = aabbccddeeff00112233445566778899


int credentialwidget::decrypter(
    QByteArray &aes256_key,
    const QByteArray &encryptedBytes,
    QByteArray &decryptedBytes
    ) {

    qDebug() << "*** aes256_key " << aes256_key.toHex();
    // Создание буфера для хранения ключа в нужном формате для OpenSSL
    unsigned char key[32] = {0};
    memcpy(key, aes256_key.data(), 32);

    QByteArray iv_hex("aabbccddeeff00112233445566778899");

    QByteArray iv_ba = QByteArray::fromHex(iv_hex);
    unsigned char iv[16] = {0};
    memcpy(iv, iv_ba.data(), 16);


    qDebug() << "*** iv_hex " << iv;

    // Инициализация контекста шифрования OpenSSL
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        // В случае ошибки инициализации контекста освобождаем память и возвращаем ошибку
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
#define BUF_LEN 256
    // Буферы для хранения зашифрованных и расшифрованных данных
    unsigned char encrypted_buf[BUF_LEN] = {0}, decrypted_buf[BUF_LEN] = {0};
    int encr_len, decr_len;

    // Создание потока для чтения зашифрованных данных
    QDataStream encrypted_stream(encryptedBytes);

    // Создание буфера для записи расшифрованных данных
    QBuffer decrypted_buffer(&decryptedBytes);
    decrypted_buffer.open(QIODevice::WriteOnly);

    // Чтение и расшифровка данных поблочно
    encr_len = encrypted_stream.readRawData(reinterpret_cast<char*>(encrypted_buf), BUF_LEN);
    while (encr_len > 0) {
        if (!EVP_DecryptUpdate(ctx, decrypted_buf, &decr_len, encrypted_buf, encr_len)) {
            // В случае ошибки расшифровки освобождаем память и возвращаем ошибку
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }
        // Записываем расшифрованные данные в буфер
        decrypted_buffer.write(reinterpret_cast<char*>(decrypted_buf), decr_len);
        // Читаем следующий блок зашифрованных данных
        encr_len = encrypted_stream.readRawData(reinterpret_cast<char*>(encrypted_buf), BUF_LEN);
    }

    // Завершаем расшифровку, записываем оставшиеся данные
    int tmplen;
    if (!EVP_DecryptFinal_ex(ctx, decrypted_buf, &tmplen)) {
        // В случае ошибки завершения расшифровки освобождаем память и возвращаем ошибку
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    decrypted_buffer.write(reinterpret_cast<char*>(decrypted_buf), tmplen);

    EVP_CIPHER_CTX_free(ctx);

    return 0;
}


void credentialwidget::on_copyLogin_clicked()
{
    QString pin = dialogPin::getPin();
    qDebug() << "***PIN -> " << pin.toUtf8();

    QByteArray hash = QCryptographicHash::hash(
        pin.toUtf8(),
        QCryptographicHash::Sha256);

    qDebug() << "***Hash -> " << hash.toHex();


    QByteArray hash_key = QByteArray::fromHex(hash.toHex());
    qDebug() << "***hash_key -> " << hash_key;

    if (checkJSON(hash_key) == 0)
    {

        QByteArray hexEncryptedLog(log_encr);
        QByteArray encryptedLog = QByteArray::fromHex(hexEncryptedLog);
        QByteArray decryptedLog;

        if (decrypter(hash, encryptedLog, decryptedLog) == 0)
        {
            QString login(decryptedLog);
            QClipboard *clipboard = QGuiApplication::clipboard();

            qDebug() << "***login -> " << login;
            clipboard->setText(login);
            QMessageBox::about(this, " ", "Скопировано");
        }

        else
        {
            ui->editLogin->setText("Error");
        }

    }

    else if (pin != "")
    {
        QMessageBox::critical(this, " ", "Неверный пин-код");
    }


}




void credentialwidget::on_copyPassword_clicked()
{
    QString pin = dialogPin::getPin();

    QByteArray hash = QCryptographicHash::hash(pin.toUtf8(), QCryptographicHash::Sha256);

    qDebug() << "***Hash -> " << hash;


    QByteArray hash_key = QByteArray::fromHex(hash.toHex());
    qDebug() << "***hash_key -> " << hash_key;

    if (checkJSON(hash_key) == 0)
    {

        qDebug() << "1";
        QByteArray hexEncryptedPass(pass_encr);
        QByteArray encryptedPass = QByteArray::fromHex(hexEncryptedPass);
        QByteArray decryptedPass;

        if (decrypter(hash, encryptedPass, decryptedPass) == 0)
        {
            QString password(decryptedPass);
            QClipboard *clipboard = QGuiApplication::clipboard();
            qDebug() << "***password -> " << password;
            clipboard->setText(password);
            QMessageBox::about(this, " ", "Скопировано");
        }

        else
        {
            ui->editPassword->setText("Eror");
        }

        return;

    }

    else if (pin != "")
    {
        QMessageBox::critical(this, " ", "Неверный пин-код");
    }
}

