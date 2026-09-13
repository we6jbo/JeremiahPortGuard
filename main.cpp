#include <QApplication>
#include <QCoreApplication>
#include <QDesktopServices>
#include <QDir>
#include <QHostAddress>
#include <QMessageBox>
#include <QProcess>
#include <QPushButton>
#include <QTcpSocket>
#include <QUrl>
#include "mainwindow.h"

namespace {
bool anotherJeremiahPortGuardIsRunning()
{
    QTcpSocket socket;
    socket.connectToHost(QHostAddress::LocalHost, 23458);
    if (!socket.waitForConnected(250))
        return false;
    socket.write("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    socket.waitForBytesWritten(250);
    QByteArray response;
    if (socket.waitForReadyRead(500))
        response += socket.readAll();
    while (socket.waitForReadyRead(50))
        response += socket.readAll();
    return response.contains("JeremiahPortGuard");
}
}

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    QCoreApplication::setOrganizationName("JeremiahONeal");
    QCoreApplication::setApplicationName("JeremiahPortGuard");
    QCoreApplication::setApplicationVersion(JPG_VERSION);

    const bool serviceMode = QCoreApplication::arguments().contains("--service");
    if (serviceMode)
        app.setQuitOnLastWindowClosed(false);

    if (!serviceMode && anotherJeremiahPortGuardIsRunning()) {
        QMessageBox box(QMessageBox::Information,
                        "JeremiahPortGuard is already running",
                        "Another JeremiahPortGuard instance is already active.\n\n"
                        "You can view its local status page or restore normal GUI Mode.\n"
                        "A second registry engine will not be started.",
                        QMessageBox::Close);
        auto *statusButton = box.addButton("Open Status Page", QMessageBox::ActionRole);
        auto *restoreButton = box.addButton("Restore GUI Mode", QMessageBox::ActionRole);
        box.exec();
        if (box.clickedButton() == statusButton) {
            QDesktopServices::openUrl(QUrl("http://127.0.0.1:23458/"));
        } else if (box.clickedButton() == restoreButton) {
            const QString helper = QDir::homePath() + "/.local/bin/jeremiah-port-guard";
            QProcess::startDetached(helper, {"gui-mode"});
        }
        return 0;
    }

    MainWindow w;
    if (!serviceMode)
        w.show();
    return app.exec();
}
