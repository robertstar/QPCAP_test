#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <pcap.h>
#include <QMutex>
#include <QSocketNotifier>

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

    QString lookupDevice();
    bool open_live( const QString &dev, int snaplen, bool promisc );
    bool readPacket();
    bool close_live();
    static void my_packet_handler(u_char *args, const struct pcap_pkthdr *packet_header, const u_char *packet);

    static void packet_callback( uchar *self, const pcap_pkthdr *header, const uchar *packet );
    void start();

signals:
    void readOK(quint32 val);
    void packetReady();
    void packetReady( const uchar *packet );
    void packetReady( const pcap_pkthdr *header, const uchar *packet );

private slots:
    void readPackets();
    void addToConsole(quint32 val);
    void print( const pcap_pkthdr *header, const uchar *packet );
    void dataAvailable();



private:
    Ui::MainWindow *ui;

    //static MainWindow *mw;



    int pkt_cnt;
    uint32_t udp_cnt_array[10];
    int i=0;
    uint16_t ip4_tlen;
    uint32_t udp_cnt;
    uint32_t udp_cnt_old=0;
    u_char val[1500];

    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    int timeout_limit = 10000; /* In milliseconds */
    const pcap_pkthdr *header;
    const u_char *packet;
    struct pcap_pkthdr packet_header;
    QString device;
    QSocketNotifier *notifier;
};

#endif // MAINWINDOW_H
