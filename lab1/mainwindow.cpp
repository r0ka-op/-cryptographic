#include "mainwindow.h"
#include "./ui_mainwindow.h"
#include "credentialwidget.h"

#include <QBuffer>
#include <QCryptographicHash>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QLineEdit>
#include <QJsonParseError>

#include <openssl/evp.h>

// password - roma



// key = b0c27fca74fa91934900c9ffcb3dcca5b807a3c059a3b516cdd0788807b5ff49
// iv = aabbccddeeff00112233445566778899

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    connect(ui->lineEdit, &QLineEdit::textEdited, this, &MainWindow::searchWidget);

}

MainWindow::~MainWindow()
{
    delete ui;
}

// Функция считывает учётные записи из файла json в структуру данных Qlist
bool MainWindow::readJSON(const QByteArray &aes256_key)
{
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
    qDebug() << "*** hexEncryptedBytes orig" << hexEncryptedBytes;

    QByteArray encryptedBytes = QByteArray::fromHex(hexEncryptedBytes);
    qDebug() << "*** hexEncryptedBytes" << encryptedBytes.toHex();

    QByteArray decryptedBytes;

    // Расшифровка зашифрованных данных с использованием ключа AES-256
    int ret_code = decryptFile(aes256_key, encryptedBytes, decryptedBytes);
    qDebug() << "*** decryptFile(), decryptedBytes = " << decryptedBytes.toHex() << "retCODE" << ret_code;

    QJsonParseError jsonErr;
    QJsonDocument jsonDoc = QJsonDocument::fromJson(decryptedBytes, &jsonErr);

    if (jsonErr.error != QJsonParseError::NoError)
        return false;

    QJsonObject rootObject = jsonDoc.object();
    qDebug() << "*** rootObject = " << rootObject;

    m_jsonarray = rootObject["cridentials"].toArray();

    if (ret_code == 0) {
        return true;
    }

    jsonFile.close();
}


// Фильтрация списка учетных записей
void MainWindow::searchWidget(const QString &searchString)
{

    ui->listWidget->clear();


    qDebug() << "searchWidget start";
    // Перебор всех учетных записей
    for (int i = 0; i != m_jsonarray.size(); ++i)

    {
        qDebug() << i;
        QJsonObject jsonItem = m_jsonarray[i].toObject();

        if ((searchString == "") || jsonItem["site"].toString().toLower().contains(searchString.toLower()))
        {
            qDebug() << "if start";
            QListWidgetItem *newItem = new QListWidgetItem();
            credentialwidget *itemWidget = new credentialwidget(jsonItem["site"].toString(), jsonItem["login"].toString(), jsonItem["password"].toString());

            ui->listWidget->addItem(newItem);
            ui->listWidget->setItemWidget(newItem, itemWidget);

            newItem->setSizeHint(itemWidget->sizeHint());
        }
    }

    qDebug() << "searchWidget stop" << Qt::endl << Qt::endl;
}

// key = 1fdf45545a89b94b956eee6ec780ecc7adf2baf4eddb8163e60b6d18c2f48adc
// iv = de1358eb7cd471c58dc76ea9a5977983


int MainWindow::decryptFile(
    const QByteArray &aes256_key,
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


    qDebug() << "*** iv_hex " << iv_hex.toHex();

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



void MainWindow::on_editPin_returnPressed()
{
    // получить ключ из пин-кода
    QByteArray hash = QCryptographicHash::hash(
        ui->editPin->text().toUtf8(),
        QCryptographicHash::Sha256);
    qDebug() << "*** text = " << ui->editPin->text().toUtf8();
    qDebug() << "*** Sha256 = " << hash.toHex();

    // расшифровать файл и проверить верность пин-кода
    // если верный - сменить панель и отрисовать список
    // если неверный - предупреждение
    if(readJSON(hash)) {
        ui->stackedWidget->setCurrentIndex(0);
        searchWidget("");

        qDebug() << "searchWidget out";
    } else {
        ui->lblLogin->setText("Неверный пин-код");
        ui->lblLogin->setStyleSheet("color:red;");
    }


    ui->editPin->setText(QString().fill('*', ui->editPin->text().size()));
    ui->editPin->clear();
    hash.setRawData(
        const_cast<char*>(QByteArray().fill('*', 32).data() ),
        32);
    hash.clear();
    // удалить ключ и пин код
}

