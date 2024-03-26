#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QJsonArray>
#include <QJsonValue>
#include <QMainWindow>
#include <QJsonArray>

class Cridential {
public:
    QString hostname;
    QString login;
    QString password;
};

QT_BEGIN_NAMESPACE
namespace Ui {
class MainWindow;
}
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    bool readJSON(const QByteArray &aes256_key);

public slots:
    //void on_lineEdit_editingFinished();
    void searchWidget(const QString & searchString);
    int decryptFile(const QByteArray &aes256_key, const QByteArray &encryptedBytes, QByteArray &decryptedBytes);

private slots:
    void on_editPin_returnPressed();

private:
    Ui::MainWindow *ui;
    QJsonArray m_jsonarray; //структура данных содержащая учетные записи
};
#endif // MAINWINDOW_H
