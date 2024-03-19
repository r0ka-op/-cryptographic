#include "dialogpin.h"
#include "ui_dialogpin.h"

dialogPin::dialogPin(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::dialogPin)
{
    ui->setupUi(this);
}

QString dialogPin::getPin(QWidget *parent)
{
    dialogPin *EnterPassword = new dialogPin();
    EnterPassword->setModal(true);
    if (EnterPassword->exec() == dialogPin::Rejected)
    {
        return "";
    }

    else
    {
        return EnterPassword->ui->passwordLineEdit->text().toUtf8();
    }

}

dialogPin::~dialogPin()
{
    delete ui;
}

void dialogPin::on_passwordLineEdit_returnPressed()
{
    accept();
}
