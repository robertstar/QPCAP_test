#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <pcap.h>
#include <QDebug>

#include <QMutex>
#include <QSocketNotifier>


MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    device = lookupDevice();
    if ( device.isEmpty() ) {
        qDebug() << "Lookup device failed, ";
    }
    else {
        qDebug() << "Lookup device" << device;
    }

    //connect(this, &MainWindow::readOK, this, SLOT(addToConsole(quint32)));
    connect(ui->readBtn, SIGNAL (released()),this, SLOT (readPackets()));
}

//void PcapWorker::parse_frame    ( u_char *user, const struct pcap_pkthdr *frame_header,  const u_char *frame_ptr)
void MainWindow::my_packet_handler( u_char *args, const struct pcap_pkthdr *packet_header, const u_char *packet)
{
    const u_char *ip_header;
    const u_char *udp_header;
    const u_char *payload;
    const u_char *ip4_tlen_p;

    int pkt_cnt;

    quint32 udp_cnt_array[10];
    int i=0;
    uint16_t ip4_tlen;
    quint32 udp_cnt;
    quint32 udp_cnt_old=0;
    u_char val[1500];

    /* Find start of IP header */
    //ip_header  = packet + 14;
    //ip4_tlen_p = packet + 16;

    memcpy(&val[0],packet,1458);
    memcpy(&ip4_tlen,&val[16],2);
    memcpy(&udp_cnt, &val[42], 4);
    //printf("ip4_tlen: %02X, %02X, %d\n", val[14], val[15], ip4_tlen);
    //qDebug() << QString(" 0x%1").arg(udp_cnt,   2, 16, QChar('0'));
    //qDebug() << "udp_cnt: " + QString::number(udp_cnt);

    //ui->textEdit->append("udp_cnt: " + QString::number(udp_cnt));

    //text = "Packet capture length: " + QString::number(header->caplen);
    //ui->textEdit->append(text);

    //emit readOK(udp_cnt);

    //MYClass::getInstance()->emitFunction(val);



    //if(m_psMainWindow)
            //m_psMainWindow->ui->textEdit->append("12");



    //MainWindow* mw = (MainWindow*)ui;


    //MainWindow* pthis = mw; // get this address

    //mw->readOK(12);

    //MainWindow *mw = reinterpret_cast<MainWindow *>(self);

    return;
}

void MainWindow::packet_callback( uchar *self, const pcap_pkthdr *header0, const uchar *packet0 )
{
    MainWindow *mw = reinterpret_cast<MainWindow *>(self);
    mw->header = header0;
    mw->packet = packet0;

    mw->packetReady();
    mw->packetReady( mw->packet );
    mw->packetReady( mw->header, mw->packet );
}

void MainWindow::dataAvailable()
{
    pcap_dispatch( handle, -1 /* all packets*/, (pcap_handler)&MainWindow::packet_callback, (uchar *)this );
}


void MainWindow::start()
{
    int fd = pcap_get_selectable_fd(handle);
    notifier = new QSocketNotifier( fd, QSocketNotifier::Read, this );
    connect( notifier, SIGNAL(activated(int)), this, SLOT(dataAvailable()) );
    notifier->setEnabled(true);
}

void MainWindow::print( const pcap_pkthdr *header, const uchar *packet )
{
    memcpy(&val[0],packet,1458);
    memcpy(&ip4_tlen,&val[16],2);
    memcpy(&udp_cnt, &val[42], 4);

    //ui->textEdit->append("udp_cnt: " + QString::number(udp_cnt));

   ui->textEdit->append("RX: " + QString::number(header->caplen) + " bytes," + " udp_cnt: " + QString::number(udp_cnt));
   //ui->textEdit->append("header->len: "    + QString::number(header->len) );
}

void MainWindow::addToConsole(uint32_t udp_cnt)
{
    ui->textEdit->append("udp_cnt: " + QString::number(udp_cnt));
}

void MainWindow::readPackets()
{
    QString text;

    bool ok;
    ok = open_live( device, 65535, true );
    if (!ok) {
        qDebug() << "Unable to open, ";
    }

    //connect( this, SIGNAL(packetReady(const uchar *)), SLOT(print(const uchar *)) );
    connect( this, SIGNAL(packetReady(const pcap_pkthdr *, const uchar *)), SLOT(print(const pcap_pkthdr *, const uchar *)) );

    //packetReady( const pcap_pkthdr *header, const uchar *packet )

    start();
    //close_live();


}

MainWindow::~MainWindow()
{
    delete ui;
}

QString MainWindow::lookupDevice()
{
    char *dev = pcap_lookupdev(error_buffer);
    if (!dev)
        return QString();

    return QString::fromLocal8Bit(dev);
}

bool MainWindow::open_live( const QString &dev, int snaplen, bool promisc )
{
    handle = pcap_open_live( dev.toLocal8Bit().constData(),
                                BUFSIZ,
                                0,//promisc,
                                timeout_limit,
                                error_buffer );

    if (handle == nullptr) {
        qDebug() << "Could not open device " + dev;
             return 0;
    }



    return 1;
}

bool MainWindow::readPacket()
{
//    int result = pcap_next_ex( handle, &header, &packet );
//    //pcap_next_ex(pcap_t *, struct pcap_pkthdr **, const u_char **);
//    if (result < 1)
//        return false;
//    //d->header.header = header;
//    return true;


//    //packet = pcap_next(handle, &packet_header);
//    //pcap_next_ex();
//    /*if (packet == nullptr) {
//       qDebug() << "No packet found!";
//       return 2;
//    }

//    return 1;*/
}

bool MainWindow::close_live()
{
    pcap_close(handle);
    return true;
}





//pcap_loop(handle, 0,  my_packet_handler, NULL);

//    for (int i=0; i < 10; i++ ) {
//        ok = readPacket();
//        if (!ok) {
//            qDebug() << "Failed to read a packet, ";
//        }


    //qDebug() << "Packet capture length: " << packet_header.caplen;

    //text = "Packet capture length: " + QString::number(header->caplen);
    //ui->textEdit->append(text);


    /*QPcapHeader header = pcap.header();
    qDebug() << "Got one packet, length is " << header.packetLength() << "captured " << header.capturedLength();

    const u_char *packet = pcap.packet();

    QPcapEthernetPacket ether(packet);
    qDebug() << "Source:" << ether.sourceHost();
    qDebug() << "Dest:" << ether.destHost();

    QPcapIpPacket ip = ether.toIpPacket();
    qDebug() << "Source:" << ip.source();
    qDebug() << "Dest:" << ip.dest();

    QByteArray bytes( (const char *)packet, header.capturedLength() );
    qDebug() << bytes.toHex();*/
//}

//close_live();
