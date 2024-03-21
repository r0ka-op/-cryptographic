#ifndef CREDENTIALWIDGET_H
#define CREDENTIALWIDGET_H

#include <QWidget>

#include "dialogPin.h"

namespace Ui { // это сгенерировано qt designer, чтобы  можно было обращаться к этому классу для всяких триггеров там и все такое
class credentialwidget;
}

class credentialwidget : public QWidget
{
    Q_OBJECT

public:
    explicit credentialwidget(QString site, QString login_encrypted, QString password_encrypted, QWidget *parent = nullptr);
    ~credentialwidget();
    bool checkJSON(QByteArray &aes256_key);
    int decrypter(QByteArray &aes256_key, const QByteArray &encryptedBytes, QByteArray &decryptedBytes);

private slots:
    void on_copyLogin_clicked();
    void on_copyPassword_clicked();


private:
    Ui::credentialwidget *ui;
    char* pass_encr;
    char* log_encr;

    dialogPin *EnterPassword;
};

#endif // CREDENTIALWIDGET_H
