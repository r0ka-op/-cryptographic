#ifndef CREDENTIALWIDGET_H
#define CREDENTIALWIDGET_H

#include <QWidget>

namespace Ui { // это сгенерировано qt designer, чтобы  можно было обращаться к этому классу для всяких триггеров там и все такое
class credentialwidget;
}

class credentialwidget : public QWidget
{
    Q_OBJECT

public:
    explicit credentialwidget(const QString&site, QWidget *parent = nullptr);
    ~credentialwidget();

private:
    Ui::credentialwidget *ui;
};

#endif // CREDENTIALWIDGET_H
