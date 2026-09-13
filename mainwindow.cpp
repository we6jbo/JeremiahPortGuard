#include "mainwindow.h"
#include "ui_mainwindow.h"

#include <QCryptographicHash>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMessageBox>
#include <QProcess>
#include <QRegularExpression>
#include <QSaveFile>
#include <QSqlError>
#include <QSqlQuery>
#include <QSqlRecord>
#include <QStandardPaths>
#include <QTableWidgetItem>
#include <QStorageInfo>
#include <QTextStream>
#include <QThread>

#include <algorithm>
#include <cmath>
#include <unistd.h>

namespace {
QString nowIso()
{
    return QDateTime::currentDateTime().toString(Qt::ISODateWithMs);
}

QString sha256File(const QString &path)
{
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly))
        return "not_available";
    QCryptographicHash hash(QCryptographicHash::Sha256);
    if (!hash.addData(&f))
        return "not_available";
    return QString::fromLatin1(hash.result().toHex());
}

QString readFirstLine(const QString &path)
{
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text))
        return {};
    return QString::fromUtf8(f.readLine()).trimmed();
}

bool writeIdentityFile(const QString &path)
{
    QSaveFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Text))
        return false;
    QJsonObject o{
        {"schema", 1},
        {"application_id", "io.github.we6jbo.JeremiahPortGuard"},
        {"project_id", "JeremiahPortGuard"},
        {"purpose", "Local port assignment registry and resource-aware authority"}
    };
    f.write(QJsonDocument(o).toJson(QJsonDocument::Indented));
    return f.commit();
}

bool identityMatches(const QString &path)
{
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly))
        return false;
    const QJsonDocument doc = QJsonDocument::fromJson(f.readAll());
    return doc.isObject() && doc.object().value("application_id").toString() ==
           "io.github.we6jbo.JeremiahPortGuard";
}

QString normalizeAddress(QString address)
{
    address = address.trimmed();
    if (address.startsWith('[') && address.contains(']'))
        address = address.mid(1, address.indexOf(']') - 1);
    if (address == "*")
        address = "0.0.0.0";
    return address;
}
}

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent), ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    setWindowTitle(QString("JeremiahPortGuard %1").arg(QCoreApplication::applicationVersion()));

    connect(ui->refreshButton, &QPushButton::clicked, this, &MainWindow::refreshAll);
    connect(ui->verifyButton, &QPushButton::clicked, this, &MainWindow::verifyDatabase);
    connect(ui->exportButton, &QPushButton::clicked, this, &MainWindow::exportSnapshot);

    connect(&refreshTimer, &QTimer::timeout, this, &MainWindow::refreshAll);
    connect(&resourceTimer, &QTimer::timeout, this, &MainWindow::updateResourceState);
    refreshTimer.start(30000);
    resourceTimer.start(5000);

    if (!locateDataDirectory()) {
        QMessageBox::critical(this, "Data directory unavailable",
            "JeremiahPortGuard could not locate an approved machine-wide data directory.\n"
            "Run the supplied install script first. No directory under /home is used for registry state.");
        setStatus("No approved data directory available.");
        return;
    }

    loadBaseline();

    if (!openDatabase() || !ensureSchema()) {
        QMessageBox::critical(this, "Database error", db.lastError().text());
        return;
    }

    seedPolicyReservations();
    previousCpu = readCpuSample();
    refreshAll();
    updateResourceState();
}

MainWindow::~MainWindow()
{
    if (db.isOpen())
        db.close();
    delete ui;
}

bool MainWindow::locateDataDirectory()
{
    const QStringList candidates = {
        "/var/lib/JeremiahPortGuard",
        "/var/lib/io.github.we6jbo.JeremiahPortGuard",
        "/usr/local/var/lib/JeremiahPortGuard",
        "/opt/JeremiahPortGuard/var/lib"
    };

    for (const QString &candidate : candidates) {
        QDir d(candidate);
        const QString marker = candidate + "/identity.json";
        if (d.exists() && identityMatches(marker)) {
            dataDir = candidate;
            identityPath = marker;
            dbPath = dataDir + "/ports.db";
            return true;
        }
    }

    for (const QString &candidate : candidates) {
        QFileInfo fi(candidate);
        if (!fi.exists())
            continue; // creation is intentionally delegated to the installer/admin
        QDir d(candidate);
        if (!d.isReadable() || !QFileInfo(candidate).isWritable())
            continue;
        const QString marker = candidate + "/identity.json";
        if (!QFileInfo::exists(marker) && writeIdentityFile(marker)) {
            dataDir = candidate;
            identityPath = marker;
            dbPath = dataDir + "/ports.db";
            return true;
        }
    }
    return false;
}

bool MainWindow::openDatabase()
{
    db = QSqlDatabase::addDatabase("QSQLITE", "JeremiahPortGuardConnection");
    db.setDatabaseName(dbPath);
    if (!db.open())
        return false;
    QSqlQuery q(db);
    q.exec("PRAGMA journal_mode=WAL");
    q.exec("PRAGMA foreign_keys=ON");
    q.exec("PRAGMA busy_timeout=5000");
    return true;
}

bool MainWindow::ensureSchema()
{
    QSqlQuery q(db);
    const QStringList statements = {
        "CREATE TABLE IF NOT EXISTS projects ("
        "project_id TEXT PRIMARY KEY, application_id TEXT NOT NULL UNIQUE, display_name TEXT NOT NULL, "
        "project_root TEXT, executable_path TEXT, executable_hash TEXT, version TEXT, owner_uid INTEGER, owner_gid INTEGER, "
        "tg_aka_identifiers TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)",

        "CREATE TABLE IF NOT EXISTS port_assignments ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, project_id TEXT, protocol TEXT NOT NULL, bind_address TEXT NOT NULL, "
        "port INTEGER NOT NULL CHECK(port BETWEEN 1 AND 65535), purpose TEXT, assignment_status TEXT NOT NULL, "
        "persistent_assignment INTEGER NOT NULL DEFAULT 0, assigned_at TEXT, last_verified_at TEXT, current_pid INTEGER, "
        "process_start_time TEXT, actual_executable_path TEXT, actual_executable_hash TEXT, is_listening INTEGER NOT NULL DEFAULT 0, "
        "actual_address TEXT, actual_port INTEGER, socket_inode TEXT, authorization_method TEXT, application_key_id TEXT, "
        "public_key_fingerprint TEXT, last_auth_success TEXT, last_auth_failure TEXT, auth_failure_count INTEGER NOT NULL DEFAULT 0, "
        "last_conflict_at TEXT, last_conflict_pid INTEGER, last_conflict_executable TEXT, last_error TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, "
        "UNIQUE(protocol, bind_address, port))",

        "CREATE TABLE IF NOT EXISTS events ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, event_type TEXT NOT NULL, project_id TEXT, protocol TEXT, "
        "address TEXT, port INTEGER, result TEXT, reason TEXT)",

        "CREATE TABLE IF NOT EXISTS resource_history ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, system_cpu_percent REAL, application_cpu_percent REAL, "
        "system_ram_percent REAL, application_ram_mib REAL, filesystem_used_percent REAL, filesystem_free_gib REAL, "
        "system_net_rx_mib_s REAL, system_net_tx_mib_s REAL, load_1m REAL, battery_percent REAL, battery_drain_percent_min REAL, ac_connected INTEGER, cpu_temperature_c REAL, "
        "thermal_throttling INTEGER, machine_health_percent REAL, requested_work_percent REAL, effective_work_percent REAL, "
        "governor_mode TEXT, throttle_reason TEXT)",

        "CREATE INDEX IF NOT EXISTS idx_ports_status ON port_assignments(assignment_status)",
        "CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)",
        "CREATE INDEX IF NOT EXISTS idx_resource_timestamp ON resource_history(timestamp)"
    };

    for (const QString &sql : statements) {
        if (!q.exec(sql)) {
            setStatus("Schema error: " + q.lastError().text());
            return false;
        }
    }

    // Forward-compatible migrations for databases created by JeremiahPortGuard v1.
    q.exec("ALTER TABLE resource_history ADD COLUMN load_1m REAL");
    q.exec("ALTER TABLE resource_history ADD COLUMN battery_drain_percent_min REAL");

    QSqlQuery p(db);
    p.prepare("INSERT OR IGNORE INTO projects(project_id, application_id, display_name, project_root, executable_path, executable_hash, version, owner_uid, owner_gid, tg_aka_identifiers, created_at, updated_at) "
              "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)");
    const QString exe = QCoreApplication::applicationFilePath();
    const QString t = nowIso();
    p.addBindValue(kProjectId);
    p.addBindValue(kApplicationId);
    p.addBindValue(kDisplayName);
    p.addBindValue("/home/we6jbo/Projects/JeremiahPortGuard");
    p.addBindValue(exe);
    p.addBindValue(sha256File(exe));
    p.addBindValue(QCoreApplication::applicationVersion());
    p.addBindValue(static_cast<qlonglong>(getuid()));
    p.addBindValue(static_cast<qlonglong>(getgid()));
    p.addBindValue(kTgCode);
    p.addBindValue(t);
    p.addBindValue(t);
    p.exec();

    return true;
}

void MainWindow::seedPolicyReservations()
{
    QSqlQuery q(db);
    const QString now = nowIso();
    for (const int port : {23458, 23459}) {
        q.prepare("INSERT OR IGNORE INTO port_assignments(project_id, protocol, bind_address, port, purpose, assignment_status, persistent_assignment, assigned_at, last_verified_at, is_listening, authorization_method, created_at, updated_at) "
                  "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)");
        q.addBindValue(kProjectId);
        q.addBindValue("TCP");
        q.addBindValue("127.0.0.1");
        q.addBindValue(port);
        q.addBindValue("Policy advisory reservation: do not choose randomly; request a managed assignment through JeremiahPortGuard. No listener is created.");
        q.addBindValue("POLICY_RESERVED");
        q.addBindValue(1);
        q.addBindValue(now);
        q.addBindValue(now);
        q.addBindValue(0);
        q.addBindValue("registry_policy_only");
        q.addBindValue(now);
        q.addBindValue(now);
        q.exec();
    }

    QJsonObject policy;
    policy["schema"] = 1;
    policy["authority_application_id"] = kApplicationId;
    policy["database_path"] = dbPath;
    policy["instruction"] = "Do not choose a random application port. Query the JeremiahPortGuard registry and request a managed assignment before creating a listener.";
    policy["network_listener_present"] = false;
    policy["client_server_authorization_required"] = "3team";
    QJsonArray reserved;
    reserved.append(23458);
    reserved.append(23459);
    policy["policy_reserved_ports"] = reserved;
    QSaveFile advisory(dataDir + "/authority_instructions.json");
    if (advisory.open(QIODevice::WriteOnly | QIODevice::Text)) {
        advisory.write(QJsonDocument(policy).toJson(QJsonDocument::Indented));
        advisory.commit();
    }
}

void MainWindow::refreshAll()
{
    if (!db.isOpen())
        return;
    scanListeners();
    loadTable();
}

void MainWindow::scanListeners()
{
    QProcess p;
    p.start("ss", {"-H", "-lntup"});
    if (!p.waitForFinished(5000)) {
        setStatus("Unable to run ss for listener discovery.");
        return;
    }

    const QString output = QString::fromUtf8(p.readAllStandardOutput());
    const QStringList lines = output.split('\n', Qt::SkipEmptyParts);
    const QString seenAt = nowIso();

    QSqlQuery reset(db);
    reset.exec("UPDATE port_assignments SET is_listening=0 WHERE assignment_status='OBSERVED_UNMANAGED'");

    const QRegularExpression pidRe("pid=(\\d+)");
    const QRegularExpression usersRe("\\(\\(\\\"([^\\\"]+)\\\"");

    for (const QString &line : lines) {
        const QStringList parts = line.simplified().split(' ');
        if (parts.size() < 5)
            continue;

        const QString protocol = parts.at(0).toUpper();
        const QString local = parts.at(4);
        const int colon = local.lastIndexOf(':');
        if (colon < 0)
            continue;
        QString address = normalizeAddress(local.left(colon));
        bool ok = false;
        const int port = local.mid(colon + 1).toInt(&ok);
        if (!ok || port < 1 || port > 65535)
            continue;

        qlonglong pid = 0;
        const auto pidMatch = pidRe.match(line);
        if (pidMatch.hasMatch())
            pid = pidMatch.captured(1).toLongLong();

        QString processName = "not_available";
        const auto userMatch = usersRe.match(line);
        if (userMatch.hasMatch())
            processName = userMatch.captured(1);

        QString actualExe = "not_available";
        QString actualHash = "not_available";
        QString processStart = "not_available";
        if (pid > 0) {
            actualExe = QFileInfo(QString("/proc/%1/exe").arg(pid)).symLinkTarget();
            if (!actualExe.isEmpty())
                actualHash = sha256File(actualExe);
            const QFileInfo statInfo(QString("/proc/%1").arg(pid));
            if (statInfo.exists())
                processStart = statInfo.birthTime().isValid() ? statInfo.birthTime().toString(Qt::ISODateWithMs) : "not_available";
        }

        QSqlQuery existing(db);
        existing.prepare("SELECT id, project_id, assignment_status FROM port_assignments WHERE protocol=? AND bind_address=? AND port=?");
        existing.addBindValue(protocol);
        existing.addBindValue(address);
        existing.addBindValue(port);
        existing.exec();

        if (existing.next()) {
            const qlonglong id = existing.value(0).toLongLong();
            const QString status = existing.value(2).toString();
            QSqlQuery u(db);
            u.prepare("UPDATE port_assignments SET last_verified_at=?, current_pid=?, process_start_time=?, actual_executable_path=?, actual_executable_hash=?, is_listening=1, actual_address=?, actual_port=?, updated_at=? WHERE id=?");
            u.addBindValue(seenAt);
            u.addBindValue(pid > 0 ? QVariant(pid) : QVariant());
            u.addBindValue(processStart);
            u.addBindValue(actualExe);
            u.addBindValue(actualHash);
            u.addBindValue(address);
            u.addBindValue(port);
            u.addBindValue(seenAt);
            u.addBindValue(id);
            u.exec();
            if (status == "POLICY_RESERVED") {
                recordEvent("POLICY_PORT_IN_USE", kProjectId, protocol, address, port, "conflict",
                            QString("Policy-reserved port is currently occupied by %1").arg(processName));
            }
        } else {
            QSqlQuery ins(db);
            ins.prepare("INSERT INTO port_assignments(project_id, protocol, bind_address, port, purpose, assignment_status, persistent_assignment, assigned_at, last_verified_at, current_pid, process_start_time, actual_executable_path, actual_executable_hash, is_listening, actual_address, actual_port, authorization_method, created_at, updated_at) "
                        "VALUES(NULL,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)");
            ins.addBindValue(protocol);
            ins.addBindValue(address);
            ins.addBindValue(port);
            ins.addBindValue(QString("Observed Linux listener (%1)").arg(processName));
            ins.addBindValue("OBSERVED_UNMANAGED");
            ins.addBindValue(0);
            ins.addBindValue(seenAt);
            ins.addBindValue(seenAt);
            ins.addBindValue(pid > 0 ? QVariant(pid) : QVariant());
            ins.addBindValue(processStart);
            ins.addBindValue(actualExe);
            ins.addBindValue(actualHash);
            ins.addBindValue(1);
            ins.addBindValue(address);
            ins.addBindValue(port);
            ins.addBindValue("observed_linux_socket");
            ins.addBindValue(seenAt);
            ins.addBindValue(seenAt);
            if (ins.exec())
                recordEvent("OBSERVED_LISTENER", "", protocol, address, port, "observed", processName);
        }
    }

    setStatus(QString("Listener scan complete: %1 listener rows observed. Database: %2").arg(lines.size()).arg(dbPath));
}

void MainWindow::loadTable()
{
    ui->portTable->setRowCount(0);
    QSqlQuery q(db);
    q.exec("SELECT COALESCE(project_id,'UNMANAGED'), protocol, bind_address, port, assignment_status, persistent_assignment, "
           "COALESCE(current_pid,''), COALESCE(actual_executable_path,''), is_listening, COALESCE(purpose,''), COALESCE(last_verified_at,'') "
           "FROM port_assignments ORDER BY port, protocol, bind_address");

    int row = 0;
    while (q.next()) {
        ui->portTable->insertRow(row);
        for (int col = 0; col < 11; ++col) {
            QString value;
            if (col == 5 || col == 8)
                value = q.value(col).toBool() ? "yes" : "no";
            else
                value = q.value(col).toString();
            ui->portTable->setItem(row, col, new QTableWidgetItem(value));
        }
        ++row;
    }
    ui->portTable->resizeColumnsToContents();
}

void MainWindow::recordEvent(const QString &eventType, const QString &projectId,
                             const QString &protocol, const QString &address, int port,
                             const QString &result, const QString &reason)
{
    QSqlQuery q(db);
    q.prepare("INSERT INTO events(timestamp,event_type,project_id,protocol,address,port,result,reason) VALUES(?,?,?,?,?,?,?,?)");
    q.addBindValue(nowIso());
    q.addBindValue(eventType);
    q.addBindValue(projectId);
    q.addBindValue(protocol);
    q.addBindValue(address);
    q.addBindValue(port > 0 ? QVariant(port) : QVariant());
    q.addBindValue(result);
    q.addBindValue(reason);
    q.exec();
}

void MainWindow::verifyDatabase()
{
    if (!db.isOpen())
        return;
    QSqlQuery q(db);
    if (!q.exec("PRAGMA integrity_check") || !q.next()) {
        QMessageBox::warning(this, "Integrity check", "Could not run SQLite integrity check.");
        return;
    }
    const QString result = q.value(0).toString();
    recordEvent("DATABASE_INTEGRITY_CHECK", kProjectId, "", "", 0,
                result == "ok" ? "success" : "failure", result);
    QMessageBox::information(this, "Integrity check", "SQLite integrity_check: " + result);
}

void MainWindow::exportSnapshot()
{
    if (!db.isOpen())
        return;

    QJsonObject root;
    root["schema"] = 1;
    root["generated_at"] = nowIso();
    root["application_id"] = kApplicationId;
    root["project_id"] = kProjectId;
    root["tg_aka_identifiers"] = kTgCode;
    root["database_path"] = dbPath;

    QJsonArray ports;
    QSqlQuery q(db);
    q.exec("SELECT project_id, protocol, bind_address, port, purpose, assignment_status, persistent_assignment, assigned_at, last_verified_at, current_pid, actual_executable_path, actual_executable_hash, is_listening FROM port_assignments ORDER BY port");
    while (q.next()) {
        QJsonObject o;
        o["project_id"] = q.value(0).isNull() ? "UNMANAGED" : q.value(0).toString();
        o["protocol"] = q.value(1).toString();
        o["bind_address"] = q.value(2).toString();
        o["port"] = q.value(3).toInt();
        o["purpose"] = q.value(4).toString();
        o["assignment_status"] = q.value(5).toString();
        o["persistent_assignment"] = q.value(6).toBool();
        o["assigned_at"] = q.value(7).toString();
        o["last_verified_at"] = q.value(8).toString();
        o["current_pid"] = q.value(9).isNull() ? QJsonValue() : QJsonValue(q.value(9).toLongLong());
        o["actual_executable_path"] = q.value(10).toString();
        o["actual_executable_hash"] = q.value(11).toString();
        o["is_listening"] = q.value(12).toBool();
        ports.append(o);
    }
    root["ports"] = ports;

    QSaveFile out(dataDir + "/ports_snapshot.json");
    if (!out.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::warning(this, "Export failed", out.errorString());
        return;
    }
    out.write(QJsonDocument(root).toJson(QJsonDocument::Indented));
    if (!out.commit()) {
        QMessageBox::warning(this, "Export failed", out.errorString());
        return;
    }
    recordEvent("SNAPSHOT_EXPORTED", kProjectId, "", "", 0, "success", dataDir + "/ports_snapshot.json");
    QMessageBox::information(this, "Snapshot exported", dataDir + "/ports_snapshot.json");
}

MainWindow::CpuSample MainWindow::readCpuSample() const
{
    QFile f("/proc/stat");
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text))
        return {};
    const QString line = QString::fromUtf8(f.readLine()).simplified();
    const QStringList p = line.split(' ');
    if (p.size() < 8 || p.at(0) != "cpu")
        return {};
    quint64 values[10] = {};
    for (int i = 1; i < p.size() && i <= 10; ++i)
        values[i - 1] = p.at(i).toULongLong();
    CpuSample s;
    for (quint64 v : values)
        s.total += v;
    s.idle = values[3] + values[4];
    s.valid = true;
    return s;
}

double MainWindow::readApplicationCpuPercent()
{
    static quint64 previousTicks = 0;
    static qint64 previousMs = 0;
    QFile f("/proc/self/stat");
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text))
        return -1.0;
    const QString line = QString::fromUtf8(f.readAll());
    const int closeParen = line.lastIndexOf(')');
    if (closeParen < 0)
        return -1.0;
    const QStringList p = line.mid(closeParen + 2).split(' ');
    if (p.size() < 15)
        return -1.0;
    const quint64 ticks = p.at(11).toULongLong() + p.at(12).toULongLong();
    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    if (previousMs == 0) {
        previousTicks = ticks;
        previousMs = now;
        return 0.0;
    }
    const long hz = sysconf(_SC_CLK_TCK);
    const double secondsCpu = double(ticks - previousTicks) / double(hz);
    const double secondsWall = double(now - previousMs) / 1000.0;
    previousTicks = ticks;
    previousMs = now;
    if (secondsWall <= 0.0)
        return 0.0;
    return std::clamp((secondsCpu / secondsWall) * 100.0, 0.0, 800.0);
}

void MainWindow::readMemory(double &systemPercent, double &appMiB) const
{
    systemPercent = appMiB = -1.0;
    QFile f("/proc/meminfo");
    if (f.open(QIODevice::ReadOnly | QIODevice::Text)) {
        qlonglong total = 0, available = 0;
        while (!f.atEnd()) {
            const QString line = QString::fromUtf8(f.readLine());
            if (line.startsWith("MemTotal:")) total = line.split(QRegularExpression("\\s+"), Qt::SkipEmptyParts).value(1).toLongLong();
            if (line.startsWith("MemAvailable:")) available = line.split(QRegularExpression("\\s+"), Qt::SkipEmptyParts).value(1).toLongLong();
        }
        if (total > 0)
            systemPercent = (double(total - available) / double(total)) * 100.0;
    }
    QFile s("/proc/self/status");
    if (s.open(QIODevice::ReadOnly | QIODevice::Text)) {
        while (!s.atEnd()) {
            const QString line = QString::fromUtf8(s.readLine());
            if (line.startsWith("VmRSS:")) {
                const qlonglong kib = line.split(QRegularExpression("\\s+"), Qt::SkipEmptyParts).value(1).toLongLong();
                appMiB = double(kib) / 1024.0;
                break;
            }
        }
    }
}

void MainWindow::readFilesystem(double &usedPercent, double &freeGiB) const
{
    QStorageInfo storage("/");
    if (!storage.isValid() || storage.bytesTotal() <= 0) {
        usedPercent = freeGiB = -1.0;
        return;
    }
    usedPercent = (1.0 - double(storage.bytesAvailable()) / double(storage.bytesTotal())) * 100.0;
    freeGiB = double(storage.bytesAvailable()) / (1024.0 * 1024.0 * 1024.0);
}

void MainWindow::readNetwork(double &rxMiBs, double &txMiBs)
{
    quint64 rx = 0, tx = 0;
    QFile f("/proc/net/dev");
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text)) {
        rxMiBs = txMiBs = -1.0;
        return;
    }
    while (!f.atEnd()) {
        const QString line = QString::fromUtf8(f.readLine());
        if (!line.contains(':'))
            continue;
        const QStringList sides = line.split(':');
        const QString iface = sides.at(0).trimmed();
        if (iface == "lo")
            continue;
        const QStringList v = sides.at(1).simplified().split(' ');
        if (v.size() >= 9) {
            rx += v.at(0).toULongLong();
            tx += v.at(8).toULongLong();
        }
    }
    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    if (previousNetMs == 0) {
        previousRxBytes = rx;
        previousTxBytes = tx;
        previousNetMs = now;
        rxMiBs = txMiBs = 0.0;
        return;
    }
    const double sec = double(now - previousNetMs) / 1000.0;
    rxMiBs = sec > 0 ? double(rx - previousRxBytes) / sec / (1024.0 * 1024.0) : 0.0;
    txMiBs = sec > 0 ? double(tx - previousTxBytes) / sec / (1024.0 * 1024.0) : 0.0;
    previousRxBytes = rx;
    previousTxBytes = tx;
    previousNetMs = now;
}

void MainWindow::readPower(double &batteryPercent, bool &acKnown, bool &acConnected) const
{
    batteryPercent = -1.0;
    acKnown = false;
    acConnected = false;
    QDir power("/sys/class/power_supply");
    for (const QString &name : power.entryList(QDir::Dirs | QDir::NoDotAndDotDot)) {
        const QString base = power.absoluteFilePath(name);
        const QString type = readFirstLine(base + "/type");
        if (type == "Battery" && batteryPercent < 0)
            batteryPercent = readFirstLine(base + "/capacity").toDouble();
        if (type == "Mains" || type == "USB" || type == "USB_C") {
            const QString online = readFirstLine(base + "/online");
            if (!online.isEmpty()) {
                acKnown = true;
                if (online == "1")
                    acConnected = true;
            }
        }
    }
}

double MainWindow::readCpuTemperature() const
{
    QDir thermal("/sys/class/thermal");
    double best = -1.0;
    for (const QString &name : thermal.entryList({"thermal_zone*"}, QDir::Dirs)) {
        bool ok = false;
        double value = readFirstLine(thermal.absoluteFilePath(name) + "/temp").toDouble(&ok);
        if (!ok)
            continue;
        if (value > 1000.0)
            value /= 1000.0;
        if (value >= 0.0 && value < 150.0)
            best = std::max(best, value);
    }
    return best;
}

double MainWindow::readLoad1() const
{
    QFile f("/proc/loadavg");
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text))
        return -1.0;
    bool ok = false;
    const double value = QString::fromUtf8(f.readLine()).section(' ', 0, 0).toDouble(&ok);
    return ok ? value : -1.0;
}

double MainWindow::updateBatteryDrain(double batteryPercent, bool acKnown, bool acConnected)
{
    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    if (!acKnown || acConnected || batteryPercent < 0.0) {
        previousBatteryPercent = batteryPercent;
        previousBatteryMs = now;
        return 0.0;
    }
    if (previousBatteryMs == 0 || previousBatteryPercent < 0.0) {
        previousBatteryPercent = batteryPercent;
        previousBatteryMs = now;
        return 0.0;
    }
    const double minutes = double(now - previousBatteryMs) / 60000.0;
    const double drop = previousBatteryPercent - batteryPercent;
    previousBatteryPercent = batteryPercent;
    previousBatteryMs = now;
    if (minutes <= 0.0)
        return 0.0;
    return std::max(0.0, drop / minutes);
}

bool MainWindow::loadBaseline()
{
    const QString path = dataDir + "/resource_baseline.json";
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly))
        return false;
    const QJsonDocument doc = QJsonDocument::fromJson(f.readAll());
    if (!doc.isObject())
        return false;
    const QJsonObject root = doc.object();
    const QJsonObject plugged = root.value("plugged_in").toObject();
    const QJsonObject unplugged = root.value("unplugged").toObject();
    const QJsonObject governor = root.value("governor").toObject();
    auto v = [](const QJsonObject &o, const char *k, double fallback) {
        const QJsonValue x = o.value(k);
        return x.isDouble() ? x.toDouble() : fallback;
    };
    baseline.pluggedCpu = v(plugged, "cpu_percent", baseline.pluggedCpu);
    baseline.pluggedRam = v(plugged, "ram_percent", baseline.pluggedRam);
    baseline.pluggedDiskUsed = v(plugged, "disk_used_percent", baseline.pluggedDiskUsed);
    baseline.pluggedLoad1 = v(plugged, "load_1m", baseline.pluggedLoad1);
    baseline.pluggedDiskWrite = v(plugged, "disk_write_mib_s", baseline.pluggedDiskWrite);
    baseline.pluggedNetRx = v(plugged, "network_in_mib_s", baseline.pluggedNetRx);
    baseline.pluggedNetTx = v(plugged, "network_out_mib_s", baseline.pluggedNetTx);
    baseline.unpluggedCpu = v(unplugged, "cpu_percent", baseline.unpluggedCpu);
    baseline.unpluggedRam = v(unplugged, "ram_percent", baseline.unpluggedRam);
    baseline.unpluggedDiskUsed = v(unplugged, "disk_used_percent", baseline.unpluggedDiskUsed);
    baseline.unpluggedLoad1 = v(unplugged, "load_1m", baseline.unpluggedLoad1);
    baseline.unpluggedDiskWrite = v(unplugged, "disk_write_mib_s", baseline.unpluggedDiskWrite);
    baseline.unpluggedNetRx = v(unplugged, "network_in_mib_s", baseline.unpluggedNetRx);
    baseline.unpluggedNetTx = v(unplugged, "network_out_mib_s", baseline.unpluggedNetTx);
    baseline.unpluggedBatteryDrain = v(unplugged, "battery_drain_percent_per_minute", baseline.unpluggedBatteryDrain);
    baseline.fullThrottleFloor = v(governor, "full_throttle_health_floor_percent", baseline.fullThrottleFloor);
    return true;
}

double MainWindow::calculateHealth(const ResourceState &r) const
{
    const bool batteryMode = r.acKnown && !r.acConnected;
    const double cpuBase = batteryMode ? baseline.unpluggedCpu : baseline.pluggedCpu;
    const double ramBase = batteryMode ? baseline.unpluggedRam : baseline.pluggedRam;
    const double diskBase = batteryMode ? baseline.unpluggedDiskUsed : baseline.pluggedDiskUsed;
    const double loadBase = batteryMode ? baseline.unpluggedLoad1 : baseline.pluggedLoad1;

    auto headroomHealth = [](double used, double baseUsed) {
        if (used < 0.0 || baseUsed >= 99.9) return 100.0;
        const double baseHeadroom = std::max(0.1, 100.0 - baseUsed);
        const double nowHeadroom = std::max(0.0, 100.0 - used);
        return std::clamp(100.0 * nowHeadroom / baseHeadroom, 0.0, 100.0);
    };

    // CPU/RAM/disk are scored as remaining headroom relative to the approved baseline.
    const double cpuHealth = headroomHealth(r.systemCpu, cpuBase);
    const double ramHealth = headroomHealth(r.ramPercent, ramBase);
    const double diskHealth = headroomHealth(r.filesystemUsedPercent, diskBase);

    double loadHealth = 100.0;
    if (r.load1 >= 0.0) {
        const double logicalCpus = std::max(1, QThread::idealThreadCount());
        const double baseHeadroom = std::max(0.25, logicalCpus - loadBase);
        const double nowHeadroom = std::max(0.0, logicalCpus - r.load1);
        loadHealth = std::clamp(100.0 * nowHeadroom / baseHeadroom, 0.0, 100.0);
    }

    double weighted = 0.35 * cpuHealth + 0.25 * ramHealth + 0.15 * diskHealth + 0.15 * loadHealth;
    double weights = 0.90;

    if (batteryMode && r.batteryDrainPercentPerMinute >= 0.0) {
        double batteryHealth = 100.0;
        const double baseDrain = std::max(0.05, baseline.unpluggedBatteryDrain);
        if (r.batteryDrainPercentPerMinute > baseDrain)
            batteryHealth = std::clamp(100.0 * baseDrain / r.batteryDrainPercentPerMinute, 0.0, 100.0);
        weighted += 0.10 * batteryHealth;
        weights += 0.10;
    }

    double health = weighted / weights;

    // Thermal and truly low-storage conditions are safety overrides, not baseline drift.
    if (r.cpuTempC >= 95.0) health = std::min(health, 50.0);
    else if (r.cpuTempC >= 90.0) health = std::min(health, 70.0);
    else if (r.cpuTempC >= 85.0) health = std::min(health, 85.0);
    if (r.filesystemFreeGiB >= 0.0 && r.filesystemFreeGiB < 5.0) health = std::min(health, 60.0);
    if (r.ramPercent >= 92.0) health = std::min(health, 55.0);

    return std::clamp(health, 0.0, 100.0);
}

int MainWindow::scanIntervalForWorkPercent(double workPercent) const
{
    if (workPercent >= 99.5) return 30000;
    if (workPercent >= 97.0) return 45000;
    if (workPercent >= 90.0) return 90000;
    if (workPercent >= 70.0) return 180000;
    if (workPercent >= 40.0) return 300000;
    return 600000; // never sleep optional work for more than ten minutes
}

void MainWindow::applyGovernor(ResourceState &r)
{
    // Smooth short-lived spikes. About 30 seconds of history at the 5-second sampler.
    smoothedHealthPercent = 0.80 * smoothedHealthPercent + 0.20 * r.machineHealthPercent;
    const double h = smoothedHealthPercent;

    if (h >= baseline.fullThrottleFloor) {
        degradedSampleCount = 0;
        ++recoverySampleCount;
        r.effectiveWorkPercent = 100.0;
        r.governorMode = "FULL";
        r.throttleReason = "within_1_percent_of_approved_baseline";
    } else {
        recoverySampleCount = 0;
        ++degradedSampleCount;

        // Do not react to one or two transient samples.
        if (degradedSampleCount < 3) {
            r.effectiveWorkPercent = 100.0;
            r.governorMode = "FULL_WATCH";
            r.throttleReason = "temporary_degradation_not_yet_sustained";
        } else if (h >= 95.0) {
            // Around five percent below baseline: decide whether this app is contributing.
            const bool appContributing = r.applicationCpu >= 2.0 || r.applicationRamMiB >= 256.0;
            r.effectiveWorkPercent = appContributing ? std::clamp(95.0 + (h - 95.0), 95.0, 99.0) : 99.0;
            r.governorMode = appContributing ? "LIGHT_THROTTLE" : "WATCH";
            r.throttleReason = appContributing ? "sustained_pressure_and_application_contribution" : "sustained_pressure_but_application_not_primary_cause";
        } else if (h >= 90.0) {
            r.effectiveWorkPercent = std::clamp(90.0 + (h - 90.0) * 1.4, 90.0, 97.0);
            r.governorMode = "LIGHT_THROTTLE";
            r.throttleReason = "sustained_resource_pressure";
        } else if (h >= 80.0) {
            r.effectiveWorkPercent = 70.0 + (h - 80.0) * 2.0;
            r.governorMode = "MODERATE_THROTTLE";
            r.throttleReason = "likely_user_noticeable_pressure";
        } else if (h >= 60.0) {
            r.effectiveWorkPercent = 40.0 + (h - 60.0) * 1.5;
            r.governorMode = "HEAVY_THROTTLE";
            r.throttleReason = "high_sustained_pressure";
        } else {
            r.effectiveWorkPercent = 10.0;
            r.governorMode = "PAUSE_OPTIONAL_WORK";
            r.throttleReason = "severe_pressure_optional_work_max_pause_600_seconds";
        }
    }

    // The lightweight 5-second monitor stays active; heavier listener scanning changes speed.
    refreshTimer.setInterval(scanIntervalForWorkPercent(r.effectiveWorkPercent));
}

void MainWindow::writeResourceSample(const ResourceState &r)
{
    QSqlQuery q(db);
    q.prepare("INSERT INTO resource_history(timestamp,system_cpu_percent,application_cpu_percent,system_ram_percent,application_ram_mib,filesystem_used_percent,filesystem_free_gib,system_net_rx_mib_s,system_net_tx_mib_s,load_1m,battery_percent,battery_drain_percent_min,ac_connected,cpu_temperature_c,thermal_throttling,machine_health_percent,requested_work_percent,effective_work_percent,governor_mode,throttle_reason) "
              "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)");
    q.addBindValue(nowIso());
    q.addBindValue(r.systemCpu);
    q.addBindValue(r.applicationCpu);
    q.addBindValue(r.ramPercent);
    q.addBindValue(r.applicationRamMiB);
    q.addBindValue(r.filesystemUsedPercent);
    q.addBindValue(r.filesystemFreeGiB);
    q.addBindValue(r.netRxMiBs);
    q.addBindValue(r.netTxMiBs);
    q.addBindValue(r.load1);
    q.addBindValue(r.batteryPercent);
    q.addBindValue(r.batteryDrainPercentPerMinute);
    q.addBindValue(r.acKnown ? QVariant(r.acConnected ? 1 : 0) : QVariant());
    q.addBindValue(r.cpuTempC);
    q.addBindValue(r.thermalThrottling ? 1 : 0);
    q.addBindValue(r.machineHealthPercent);
    q.addBindValue(r.requestedWorkPercent);
    q.addBindValue(r.effectiveWorkPercent);
    q.addBindValue(r.governorMode);
    q.addBindValue(r.throttleReason);
    q.exec();

    QSqlQuery prune(db);
    prune.exec("DELETE FROM resource_history WHERE id NOT IN (SELECT id FROM resource_history ORDER BY id DESC LIMIT 17280)");
}

void MainWindow::updateResourceState()
{
    if (!db.isOpen())
        return;

    ResourceState r;
    const CpuSample nowCpu = readCpuSample();
    if (previousCpu.valid && nowCpu.valid && nowCpu.total > previousCpu.total) {
        const quint64 totalDelta = nowCpu.total - previousCpu.total;
        const quint64 idleDelta = nowCpu.idle - previousCpu.idle;
        r.systemCpu = 100.0 * (1.0 - double(idleDelta) / double(totalDelta));
    }
    previousCpu = nowCpu;

    r.applicationCpu = readApplicationCpuPercent();
    readMemory(r.ramPercent, r.applicationRamMiB);
    readFilesystem(r.filesystemUsedPercent, r.filesystemFreeGiB);
    readNetwork(r.netRxMiBs, r.netTxMiBs);
    readPower(r.batteryPercent, r.acKnown, r.acConnected);
    r.load1 = readLoad1();
    r.batteryDrainPercentPerMinute = updateBatteryDrain(r.batteryPercent, r.acKnown, r.acConnected);
    r.cpuTempC = readCpuTemperature();
    r.thermalThrottling = (r.cpuTempC >= 90.0);
    r.machineHealthPercent = calculateHealth(r);
    applyGovernor(r);

    lastResource = r;
    writeResourceSample(r);

    QJsonObject governorStatus{
        {"schema", 1},
        {"updated_at", nowIso()},
        {"approved_baseline", "T14 September 13 2026 approved baseline"},
        {"raw_health_percent", r.machineHealthPercent},
        {"smoothed_health_percent", smoothedHealthPercent},
        {"full_throttle_floor_percent", baseline.fullThrottleFloor},
        {"requested_work_percent", r.requestedWorkPercent},
        {"effective_work_percent", r.effectiveWorkPercent},
        {"governor_mode", r.governorMode},
        {"reason", r.throttleReason},
        {"listener_scan_interval_seconds", refreshTimer.interval() / 1000},
        {"application_cpu_percent", r.applicationCpu},
        {"application_ram_mib", r.applicationRamMiB},
        {"system_cpu_percent", r.systemCpu},
        {"system_ram_percent", r.ramPercent},
        {"filesystem_used_percent", r.filesystemUsedPercent},
        {"load_1m", r.load1},
        {"battery_percent", r.batteryPercent},
        {"battery_drain_percent_per_minute", r.batteryDrainPercentPerMinute},
        {"cpu_temperature_c", r.cpuTempC}
    };
    QSaveFile governorFile(dataDir + "/governor_status.json");
    if (governorFile.open(QIODevice::WriteOnly | QIODevice::Text)) {
        governorFile.write(QJsonDocument(governorStatus).toJson(QJsonDocument::Indented));
        governorFile.commit();
    }

    ui->cpuValue->setText(r.systemCpu < 0 ? "n/a" : QString::number(r.systemCpu, 'f', 2) + "%");
    ui->ramValue->setText(r.ramPercent < 0 ? "n/a" : QString::number(r.ramPercent, 'f', 2) + "%");
    ui->diskValue->setText(r.filesystemUsedPercent < 0 ? "n/a" : QString::number(r.filesystemUsedPercent, 'f', 2) + "%");
    ui->batteryValue->setText(r.batteryPercent < 0 ? "n/a" : QString::number(r.batteryPercent, 'f', 1) + "%");
    ui->healthValue->setText(QString("%1% (smoothed %2%)")
                             .arg(r.machineHealthPercent, 0, 'f', 2)
                             .arg(smoothedHealthPercent, 0, 'f', 2));
    ui->governorValue->setText(QString("%1 (%2% work, scan %3s)")
                               .arg(r.governorMode)
                               .arg(r.effectiveWorkPercent, 0, 'f', 1)
                               .arg(refreshTimer.interval() / 1000));
}

void MainWindow::setStatus(const QString &message)
{
    ui->statusLabel->setText(message);
}
