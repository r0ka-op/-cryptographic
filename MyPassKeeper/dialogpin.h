#ifndef DIALOGPIN_H
#define DIALOGPIN_H

#include <QDialog>

namespace Ui {
class dialogPin;
}

class dialogPin : public QDialog
{
    Q_OBJECT

public:
    explicit dialogPin(QWidget *parent = nullptr);
    static QString getPin(QWidget *parent = nullptr);
    ~dialogPin();

private slots:
    void on_passwordLineEdit_returnPressed();

private:
    Ui::dialogPin *ui;

signals:
    void sendData(QString pin);
};

#endif // DIALOGPIN_H



