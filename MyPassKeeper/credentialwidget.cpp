#include "credentialwidget.h"
#include "ui_credentialwidget.h"

credentialwidget::credentialwidget(const QString &site, QWidget *parent)
    :QWidget(parent)
    , ui(new Ui::credentialwidget)
{
    ui->setupUi(this);
    ui->lblSite->setText(site);
}

credentialwidget::~credentialwidget()
{
    delete ui;
}
