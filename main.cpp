#include <QApplication>
#include <QCoreApplication>
#include "mainwindow.h"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    QCoreApplication::setOrganizationName("JeremiahONeal");
    QCoreApplication::setApplicationName("JeremiahPortGuard");
    QCoreApplication::setApplicationVersion(JPG_VERSION);

    MainWindow w;
    w.show();
    return app.exec();
}
