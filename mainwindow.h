#pragma once

#include <QMainWindow>
#include <QSqlDatabase>
#include <QTimer>
#include <QJsonObject>
#include <QDateTime>
#include <QSet>
#include <QTcpServer>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow final : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow() override;

private slots:
    void refreshAll();
    void exportSnapshot();
    void verifyDatabase();
    void updateResourceState();
    void contactWesternHillsAgentPeriodic();
    void viewGuide();
    void printGuide();
    void enableServiceMode();
    void conflictPopupPreferenceChanged(bool checked);
    void handleWebConnection();

private:
    struct CpuSample {
        quint64 total = 0;
        quint64 idle = 0;
        bool valid = false;
    };

    struct ResourceState {
        double systemCpu = -1.0;
        double applicationCpu = -1.0;
        double ramPercent = -1.0;
        double applicationRamMiB = -1.0;
        double filesystemUsedPercent = -1.0;
        double filesystemFreeGiB = -1.0;
        double netRxMiBs = -1.0;
        double netTxMiBs = -1.0;
        double load1 = -1.0;
        double batteryPercent = -1.0;
        double batteryDrainPercentPerMinute = -1.0;
        bool acKnown = false;
        bool acConnected = false;
        double cpuTempC = -1.0;
        bool thermalThrottling = false;
        double machineHealthPercent = 100.0;
        double requestedWorkPercent = 100.0;
        double effectiveWorkPercent = 100.0;
        QString governorMode = "FULL";
        QString throttleReason = "baseline_or_better";
    };

    Ui::MainWindow *ui;
    QSqlDatabase db;
    QTimer refreshTimer;
    QTimer resourceTimer;
    QTimer westernHillsTimer;
    QTcpServer webServer;
    QString dataDir;
    QString dbPath;
    QString identityPath;
    CpuSample previousCpu;
    quint64 previousRxBytes = 0;
    quint64 previousTxBytes = 0;
    qint64 previousNetMs = 0;
    ResourceState lastResource;
    double smoothedHealthPercent = 100.0;
    int degradedSampleCount = 0;
    int recoverySampleCount = 0;
    double previousBatteryPercent = -1.0;
    qint64 previousBatteryMs = 0;
    QDateTime lastWesternHillsAttempt;
    QDateTime lastWesternHillsSuccess;
    QDateTime lastUncertaintyConsult;
    QSet<QString> consultedUncertaintyReasons;
    QSet<QString> shownConflictKeys;
    bool serviceMode = false;
    bool suppressConflictPopups = false;

    struct Baseline {
        double pluggedCpu = 12.34;
        double pluggedRam = 37.51;
        double pluggedDiskUsed = 63.61;
        double pluggedLoad1 = 1.192;
        double pluggedDiskWrite = 0.6842;
        double pluggedNetRx = 0.12802;
        double pluggedNetTx = 0.00631;
        double unpluggedCpu = 17.59;
        double unpluggedRam = 38.26;
        double unpluggedDiskUsed = 63.70;
        double unpluggedLoad1 = 1.791;
        double unpluggedDiskWrite = 0.4812;
        double unpluggedNetRx = 0.12195;
        double unpluggedNetTx = 0.01215;
        double unpluggedBatteryDrain = 0.392;
        double fullThrottleFloor = 99.0;
    } baseline;

    static constexpr const char *kProjectId = "JeremiahPortGuard";
    static constexpr const char *kApplicationId = "io.github.we6jbo.JeremiahPortGuard";
    static constexpr const char *kDisplayName = "JeremiahPortGuard";
    static constexpr const char *kTgCode = "TG333041";

    bool locateDataDirectory();
    bool openDatabase();
    bool ensureSchema();
    void seedPolicyReservations();
    void scanListeners();
    void loadTable();
    void setStatus(const QString &message);
    void recordEvent(const QString &eventType, const QString &projectId,
                     const QString &protocol, const QString &address, int port,
                     const QString &result, const QString &reason);

    CpuSample readCpuSample() const;
    double readApplicationCpuPercent();
    void readMemory(double &systemPercent, double &appMiB) const;
    void readFilesystem(double &usedPercent, double &freeGiB) const;
    void readNetwork(double &rxMiBs, double &txMiBs);
    void readPower(double &batteryPercent, bool &acKnown, bool &acConnected) const;
    double readLoad1() const;
    double updateBatteryDrain(double batteryPercent, bool acKnown, bool acConnected);
    bool loadBaseline();
    void applyGovernor(ResourceState &r);
    int scanIntervalForWorkPercent(double workPercent) const;
    double readCpuTemperature() const;
    double calculateHealth(const ResourceState &r) const;
    void writeResourceSample(const ResourceState &r);
    bool performWesternHillsAgentSession(const QString &reason, bool uncertaintyTriggered);
    void requestWesternHillsAgentHelp(const QString &reason);
    void scheduleNextWesternHillsContact(bool lastAttemptSucceeded);
    void writeWesternHillsStatus(bool success, const QString &reason, const QString &detail,
                                 const QJsonObject &responses);
    bool startLocalStatusServer();
    QByteArray buildStatusHtml() const;
    QString guideHtml() const;
    void showPortConflictAlert(const QString &key, const QString &protocol, const QString &address, int port, const QString &details);
    bool setGuiAutostartEnabled(bool enabled) const;
    bool systemctlUser(const QStringList &arguments, QString *output = nullptr) const;

};
