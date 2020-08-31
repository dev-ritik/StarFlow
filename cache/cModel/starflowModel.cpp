#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <pthread.h>

#include <stdlib.h>

#include <iostream>
#include <fstream>
#include <cstring>
#include <vector>
#include <list>

#include <queue>
#include <zconf.h>
#include <atomic>
#include <tuple>

using namespace std;

#include "starFlow.h"

// ./mCLFR_cache ~/datasets/caida2015/caida2015_02_dirA.pcap 60000 2 8192 5 2048 16
// ./mCLFR_cache ~/datasets/caida2015/caida2015_02_dirA.pcap 60000 8 8192 5 2048 16
// Arguments: 
// filename, training time, lru chain length 
// partition 1 length, partition 1 width 
// partition 2 length, partition 2 width

// Static options.
#define TRACE_TYPE 0 // Trace type: 0 = ethernet, 1 = ip4v (i.e., caida)
#define UPDATE_CT 1000 // Print stats every UPDATE_CT packets.

std::atomic<uint64_t> maxLastAccessTs;
std::atomic<uint64_t> sumLastAccessTs;
std::atomic<uint64_t> gtOneSecondInCache;
std::atomic<uint64_t> gtFiveSecondInCache;

char *outputFile = "mCLFRs.bin";
ofstream o;
bool dump = true;
// args.
char *source;
uint64_t trainingTime, lruChainLen, partition1Len, partition1Width, partition2Len, partition2Width;

// table variables.
// number of LRU chains. 
uint64_t htLen;
// the fixed width cache.
// hash --> LRU chain (MCLFR, MCLFR, ...)
// the mclfr feature vectors are limited to partition1Width entries. 
MCLFR **LRUChains;

//MCLFR oldCLFR;

// the long packet feature vectors.
// index --> (fixed len feature vector)
//PacketFeatures **longVectors;

std::atomic<uint32_t> stackTop;
uint32_t *longVectorStack;


//uint64_t lastLongUse[1024] = {0};
//uint64_t accessCounts[1024] = {0};


// logging and output. 
std::atomic<uint64_t> globalPktCt, globalMfCt, globalMissCt;
uint64_t globalFinMfCt;
std::atomic<uint64_t> allocFailEvicts, lruEvicts, oversizeEvicts, shortRollovers, longRollovers;

uint64_t startTs;
std::atomic<uint64_t> maxTs;

std::vector<Export_MCLFR> mCLFR_out;

queue<OriginalPacket *> packetQueue;

#define NUM_THREADS 5
pthread_t threads[NUM_THREADS];
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t slotMutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t condition = PTHREAD_COND_INITIALIZER;

std::atomic<bool> done = ATOMIC_VAR_INIT(false);
clock_t start_time;

[[noreturn]] void *waitFunction(void *arg);

void dumpCtFile();

void dumpMClfrs();

void readMClfrs(char *source);

void printStats();

void checkCorrectness();

void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet);

void packetRoutine(OriginalPacket *pkt);

// PFE cache functions.
// set up the tables. 
void initTables() {
    // Set up the LRU chains.
    htLen = partition1Len / lruChainLen;
    LRUChains = new MCLFR *[htLen];
    for (int i = 0; i < htLen; i++) {
        LRUChains[i] = new MCLFR[lruChainLen];
        memset(LRUChains[i], 0, sizeof(MCLFR) * lruChainLen);
    }
    // Set up the long packet feature vectors.
//    longVectors = new PacketFeatures *[partition2Len];
//    for (int i = 0; i < partition2Len; i++) {
//        longVectors[i] = new PacketFeatures[partition2Width];
//        memset(longVectors[i], 0, sizeof(PacketFeatures) * partition2Width);
//    }
    // Set up the long vector stack.
    // bottom entry of stack should never be touched.
    longVectorStack = new uint32_t[partition2Len];
    for (int i = 0; i < partition2Len; i++) {
        longVectorStack[stackTop] = i;
        stackTop++;
    }
    stackTop--;
}

#define SLOT_MATCH 0
#define SLOT_FREE 1
#define SLOT_EVICT 2
#define PACKET_EVICT 3

tuple<uint64_t, short int> getSlotId(u_int64_t, PacketRecord *);

// processing logic.
void initMfr(MCLFR *, PacketRecord *);

void evictMfr(MCLFR *chainItem, MCLFR *evictedMFR);

void shortAppend(MCLFR *, PacketRecord *, MCLFR *);

void longAppend(MCLFR *, PacketRecord *, MCLFR *);

void exportMfr(MCLFR *);

// helpers.
void allocLongPointer(MCLFR *);

void appendRecord(MCLFR *, PacketRecord *);

// main.
void handlePacket(PacketRecord *);

// cleanup.
void finalFlush();

//MCLFR evictedMFR; // mCLFR that is going to be evicted.


// main packet processing function.
void handlePacket(PacketRecord *pr) {
//    if ((trainingTime > 0) && ((pr->features.ts) > trainingTime * 1000)) {
////        cout << "exiting training: " << pr->features.ts << " : " << trainingTime << endl;
//        done = true;
//        return;
//    }
    globalPktCt++;

    uint64_t hashVal;
    uint64_t slotId;
    short int slotType;

    // Compute hash.
    hashVal = simpleHash(1, pr->key, KEYLEN, htLen);
    // Get the layer 1 slot -- either a match, free slot, or oldest entry.
    // get slot id.

    pthread_mutex_lock(&slotMutex);
    auto tup = getSlotId(hashVal, pr);
    slotId = get<0>(tup);
    slotType = get<1>(tup);

    MCLFR evictedMFR;
    // Main processing pipeline.

    switch (slotType) {

        // FREE SLOT pipeline -- just set new record.
        case SLOT_FREE:
//             cout << "initializing ( " << hashVal << ", " << slotId << " ) pktCt: " << LRUChains[hashVal][slotId].pktCt << endl;
            initMfr(&LRUChains[hashVal][slotId], pr);
            break;
            // EVICT SLOT pipeline -- read prior record, free prior long pointer, set record.
        case SLOT_EVICT:
//            cout << "evicting ( " << hashVal << ", " << slotId << " ) pktCt: " << LRUChains[hashVal][slotId].pktCt
//                 << endl;
            evictMfr(&LRUChains[hashVal][slotId], &evictedMFR);
            initMfr(&LRUChains[hashVal][slotId], pr);
            exportMfr(&evictedMFR);
            break;
            // MATCH SLOT pipeline -- append to short, alloc+append long, or append to long.
        case SLOT_MATCH:
//             cout << "incrementing ( " << hashVal << ", " << slotId << " ) pktCt: " << LRUChains[hashVal][slotId].pktCt << endl;

            // get the long pointer if eligible.
            allocLongPointer(&LRUChains[hashVal][slotId]);

            if (LRUChains[hashVal][slotId].longVectorIdx == 0) {
                shortAppend(&LRUChains[hashVal][slotId], pr, &evictedMFR);
            } else {
                longAppend(&LRUChains[hashVal][slotId], pr, &evictedMFR);
            }
            break;
        case PACKET_EVICT:
//            cout << "Throwing this packet ( " << hashVal << ", " << slotId << " ) pktCt: "
//                 << LRUChains[hashVal][slotId].pktCt << endl;
            initMfr(&evictedMFR, pr);
            evictedMFR.pktCt += 1;
            exportMfr(&evictedMFR);
            break;
        default:
            cout << "invalid switch case" << slotType << endl;
    }

    // Stats stuff.
    if (globalPktCt % UPDATE_CT == 0) {
        printStats();
    }

    pthread_mutex_unlock(&slotMutex);
}

tuple<uint64_t, short int> getSlotId(uint64_t hashVal, PacketRecord *pr) {
    // Scan list for match, inUse entry, or oldest entry.
    bool hasMatch = false;
    uint64_t matchPos;
    bool hasFree = false;
    bool hasOld = false;
    uint64_t freePos;
    uint64_t oldestPos;
    uint64_t oldestTs = pr->features.ts + 1;

    for (uint64_t cPos = 0; cPos < lruChainLen; cPos++) {
        // printMfrInfo(LRUChains[hashVal][cPos]);
        // Check match.
        if (memcmp(LRUChains[hashVal][cPos].key, pr->key, KEYLEN) == 0) {
            hasMatch = true;
            matchPos = cPos;
            break;
        }
        // Check for older entry.
        // cout << "\ttses: " << LRUChains[hashVal][cPos].lastAccessTs << " vs " << oldestTs << endl;
        if (LRUChains[hashVal][cPos].lastAccessTs < oldestTs) {
            hasOld = true;
            oldestTs = LRUChains[hashVal][cPos].lastAccessTs;
            oldestPos = cPos;
            // cout << "\toldestPos: " << oldestPos << endl;
        }
        // Check for null entry.
        if (!hasFree && (!LRUChains[hashVal][cPos].inUse)) {
            hasFree = true;
            freePos = cPos;
        }
    }
    if (hasMatch) {
        return {matchPos, SLOT_MATCH};
    } else if (hasFree) {
        return {freePos, SLOT_FREE};
    } else if (hasOld) {
        return {oldestPos, SLOT_EVICT};
    } else {
        return {-1, PACKET_EVICT};
    }
}


// Final evict.
void finalFlush() {
    MCLFR evictedMFR;
    uint64_t finalFlushCt = 0;
    for (int i = 0; i < htLen; i++) {
        for (int j = 0; j < lruChainLen; j++) {
            if (LRUChains[i][j].inUse) {
                finalFlushCt++;
                evictMfr(&LRUChains[i][j], &evictedMFR);
                exportMfr(&evictedMFR);
            }
        }
    }
    cout << "flushed " << finalFlushCt << " entries " << endl;

}


// dump all the MCLFRs to a file. 
void dumpMClfrs() {
    //Export_MCLFR
    cout << "dumping mCLFRs to: " << outputFile << endl;
    // ofstream o(outputFile, ios::binary);
    uint64_t ct = mCLFR_out.size();
    o.write((char *) &ct, sizeof(ct));
    for (auto mclfr : mCLFR_out) {
        o.write((char *) &mclfr.packedKey, KEYLEN);
        o.write((char *) &mclfr.flowFeatures.th_flags, sizeof(mclfr.flowFeatures.th_flags));
        o.write((char *) &mclfr.flowFeatures.pktCt, sizeof(mclfr.flowFeatures.pktCt));
        o.write((char *) mclfr.packetVector, sizeof(PacketFeatures) * mclfr.flowFeatures.pktCt);
    }
    cout << "\twrote " << ct << " mCLFRs" << endl;
    o.close();

    // Make sure its right.
    // readMClfrs(outputFile);
}

void dumpCtFile() {
    cout << "\twrote " << globalMfCt << " mCLFRs to " << outputFile << endl;
    o.close();

    // readMClfrs(outputFile);
}

// // Read mCLFRs and reassembly into vector format.
// void readMClfrs(char * source){
//   cout << "reading mCLFRs from: " << source << endl;
//   uint64_t ct = 0;
//   Export_MCLFR inMclfr;
//   ifstream insz(string(source)+string(".len"), ios::binary);
//   insz.read((char*)&ct, sizeof(ct));
//   insz.close();
//   cout << "reading " << ct << " mCLFRs" << endl;

//   ifstream in(source, ios::binary);
//   std::unordered_map<std::string, CLFR> CLFRTable;
//   std::unordered_map<std::string, CLFR> CLFRTable_fin;
//   CLFR tmpClfr;
//   Export_MCLFR tmpMClfr;
//   for (int i=0; i<ct; i++){
//     // read header values into tmp clfr.
//     in.read((char*)tmpClfr.key, KEYLEN);
//     in.read((char*)&tmpClfr.th_flags, sizeof(tmpClfr.th_flags));
//     in.read((char*)&tmpMClfr.pktCt, sizeof(tmpMClfr.pktCt));
//     tmpClfr.pktCt = (uint32_t)tmpMClfr.pktCt;
//     tmpClfr.keyStr = std::string(tmpClfr.key, KEYLEN);

//     // emplace tmp clfr into map.
//     CLFRTable.emplace(tmpClfr.keyStr, tmpClfr);

//     // evict here based on TCP flag.

//     // read features into tmp vector.
//     in.read((char*)tmpMClfr.packetVector, sizeof(PacketFeatures)*tmpMClfr.pktCt);
//     // iterate through features and insert.
//     for (int j = 0; j<tmpClfr.pktCt; j++){
//       CLFRTable[tmpClfr.keyStr].byteCounts.push_back(tmpMClfr.packetVector[j].byteCt);
//       CLFRTable[tmpClfr.keyStr].timeStamps.push_back(tmpMClfr.packetVector[j].ts);
//       CLFRTable[tmpClfr.keyStr].queueSizes.push_back(tmpMClfr.packetVector[j].queueSize);
//     }
//   }
//   cout << "done reading microflows" << endl;
//   // Done.
//   in.close();
// }

void printStats() {
    cout << "FINAL STATS:" << endl;
    cout << "---------------------- trace time (usec): " << maxTs << " ----------------------" << endl;
    cout << "\t # packets processed: " << globalPktCt << endl;
    cout << "\t # packets missed: " << globalMissCt << endl;
    cout << "\t # GPVs generated: " << globalMfCt << endl;
    cout << "\t GPV to packet ratio: " << float(globalMfCt) / float(globalPktCt) << endl;
    cout << "\t # evicts: " << lruEvicts << endl;
    cout << "\t # rollovers in short partition: " << shortRollovers << endl;
    cout << "\t # rollovers in long partition: " << longRollovers << endl;
    // cout << "\t mfs with fin flags: " << globalFinMfCt << endl;
//    cout << "\t avg time in cache (usec): " << float(sumLastAccessTs) / float(globalMfCt) << endl;
//    cout << "\t max time in cache: " << maxLastAccessTs << endl;
//    cout << "\t # flows that spent more than 1 second in cache: " << gtOneSecondInCache << endl;
//    cout << "\t # flows that spent more than 5 seconds in cache: " << gtFiveSecondInCache << endl;
    cout << "\t # Time taken: " << (double) ((double) clock() - start_time) / CLOCKS_PER_SEC << endl;
    cout << "------------------------------------------------------------------" << endl;
}

int main(int argc, char *argv[]) {
    start_time = clock();
    if (argc != 8) {
        cout
                << "incorrect number of arguments. Need 7. filename, training time, lru chain length, partition 1 length, partition 1 width, partition 2 length, partition 2 width."
                << endl;
        exit(0);
    }
    source = argv[1];
    cout << "reading from file: " << source << endl;
    trainingTime = atoi(argv[2]);
    lruChainLen = atoi(argv[3]);
    partition1Len = atoi(argv[4]);
    partition1Width = atoi(argv[5]);
    partition2Len = atoi(argv[6]);
    partition2Width = atoi(argv[7]);
    cout << "params: " << " trainingTime: " << trainingTime << " lruChainLen: " << lruChainLen << " partition1Len:"
         << partition1Len << " partition1Width: " << partition1Width << " partition2Len: " << partition2Len
         << " partition2Width: " << partition2Width << endl;

    initTables();
    cout << "tables initialized." << endl;

    if (dump) {
        cout << "dumping mCLFRs to: " << outputFile << endl;
        o.open(outputFile, ios::binary);
    }

    for (unsigned long &thread : threads) {
        pthread_create(&thread, nullptr, waitFunction, nullptr);
//        cout << "creating thread, " << thread << endl;
    }

    // Process packets.
    pcap_t *descr;
    char errbuf[PCAP_ERRBUF_SIZE];
    // open capture file for offline processing
//    descr = pcap_open_offline(source, errbuf);
    descr = pcap_open_live(source, 65535, 0, -1, errbuf);
    if (descr == nullptr) {
        cerr << "pcap_open_live() failed: " << errbuf << endl;
        return 1;
    }
    // start packet processing loop, just like live capture
    int pcap_loop_ret = pcap_loop(descr, 0, packetHandler, (u_char *) descr);
    if (pcap_loop_ret == PCAP_ERROR_BREAK) {
        cout << "Pcap Loop terminated" << endl;
    } else if (pcap_loop_ret < 0) {
        cerr << "pcap_loop() failed: " << pcap_geterr(descr);
        return 1;
    }

    done = true;
    pthread_mutex_lock(&mutex);
    pthread_cond_signal(&condition);
    pthread_mutex_unlock(&mutex);
    for (unsigned long &thread : threads) {
        pthread_join(thread, nullptr);
    }

    if (dump) {
        finalFlush();
        dumpCtFile();
        // dumpMClfrs();
    }

    printStats();

    exit(0);
}

// The packet handler that implements the flow record generator.
void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    auto *org = (OriginalPacket *) malloc(sizeof(OriginalPacket));

    org->hdr = (pcap_pkthdr *) malloc(sizeof(pcap_pkthdr));
    memcpy(org->hdr, pkthdr, sizeof(pcap_pkthdr));

    org->pkt = (u_char *) malloc(sizeof(u_char *) * pkthdr->caplen);
    memcpy(org->pkt, packet, pkthdr->caplen);

    if (startTs == 0) {
        packetRoutine(org);
    } else {
        if (done) {
            pcap_breakloop((pcap_t *) userData);
        }
        pthread_mutex_lock(&mutex);
        packetQueue.push(org);
        pthread_cond_signal(&condition);
        pthread_mutex_unlock(&mutex);
    }
}

[[noreturn]] void *waitFunction(void *arg) {
    while (true) {
        pthread_mutex_lock(&mutex);
        if (packetQueue.empty()) {
            if (done) {
                pthread_cond_signal(&condition);
                pthread_mutex_unlock(&mutex);
                pthread_exit(nullptr);
            }
            pthread_cond_wait(&condition, &mutex);
            if (packetQueue.empty()) {
                pthread_mutex_unlock(&mutex);
                continue;
            }
        }
        OriginalPacket *val = packetQueue.front();
        packetQueue.pop();
        pthread_mutex_unlock(&mutex);
        if (val != nullptr) {
            packetRoutine(val);
        }
    }
}

void packetRoutine(OriginalPacket *pkt) {
    const struct pcap_pkthdr *pkthdr = pkt->hdr;
    u_char *packet = pkt->pkt;
    const struct ether_header *ethernetHeader;
    const struct ip *ipHeader;
    const struct tcphdr *tcpHeader;
    const struct udphdr *udpHeader;

//    free(pkt);
    uint64_t curTs;

    // Set global timestamp relative to start of pcap.
    if (startTs == 0) {
        startTs = getMicrosecondTs(pkthdr->ts.tv_sec, pkthdr->ts.tv_usec);
    }
    curTs = getMicrosecondTs(pkthdr->ts.tv_sec, pkthdr->ts.tv_usec) - startTs;

//    read-modify-write operation
    uint64_t oldValue = maxTs.load();
    while (curTs > oldValue) {
        if (maxTs.compare_exchange_weak(oldValue, curTs))
            break; // Succeeded updating.
    }

    // Get IP header.
    if (TRACE_TYPE == 0) {
        ethernetHeader = (struct ether_header *) packet;
        if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) {
            ipHeader = (struct ip *) (packet + sizeof(struct ether_header));
        } else if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_ARP) {
//            cout << "ETHERTYPE_ARP" << endl;
            globalMissCt++;
            return;
        } else if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_PUP) {
//            cout << "ETHERTYPE_PUP" << endl;
            globalMissCt++;
            return;
        } else if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_SPRITE) {
//            cout << "ETHERTYPE_SPRITE" << endl;
            globalMissCt++;
            return;
        } else if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_ARP) {
//            cout << "APR Packet" << endl;
            globalMissCt++;
            return;
        } else if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_REVARP) {
//            cout << "ETHERTYPE_REVARP" << endl;
            globalMissCt++;
            return;
        } else if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_AT) {
//            cout << "ETHERTYPE_AT" << endl;
            globalMissCt++;
            return;
        } else if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_AARP) {
//            cout << "ETHERTYPE_AARP" << endl;
            globalMissCt++;
            return;
        } else if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_VLAN) {
//            cout << "ETHERTYPE_VLAN" << endl;
            globalMissCt++;
            return;
        } else if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IPX) {
//            cout << "ETHERTYPE_IPX" << endl;
            globalMissCt++;
            return;
        } else if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IPV6) {
//            cout << "ETHERTYPE_IPV6" << endl;
            globalMissCt++;
            return;
        } else if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_LOOPBACK) {
//            cout << "ETHERTYPE_LOOPBACK" << endl;
            globalMissCt++;
            return;
        } else {
            globalMissCt++;
            return;
        }
    } else if (TRACE_TYPE == 1) {
        ipHeader = (struct ip *) (packet);
    }

    PacketRecord pr{};
    // Parse packet into microflow format.
    if (ipHeader->ip_p == 6) {
        tcpHeader = (tcphdr *) ((u_char *) ipHeader + sizeof(*ipHeader));
        // Set raw key.
        setKey(pr.key, ipHeader, (const udphdr *) tcpHeader);
        pr.th_flags = tcpHeader->th_flags;
        pr.features.byteCt = ipHeader->ip_len;
        pr.features.ts = curTs;
        pr.features.queueSize = 1;

        handlePacket(&pr);
    } else if (ipHeader->ip_p == 17) {
        udpHeader = (udphdr *) ((u_char *) ipHeader + sizeof(*ipHeader));
        // Set raw key.
        setKey(pr.key, ipHeader, udpHeader);
        pr.th_flags = 0;
        pr.features.byteCt = ipHeader->ip_len;
        pr.features.ts = curTs;
        pr.features.queueSize = 1;

        handlePacket(&pr);
    } else {
        globalMissCt++;
    }
}

/*=================================
=            New stuff            =
=================================*/



void initMfr(MCLFR *chainItem, PacketRecord *pr) {
    chainItem->firstAccessTs = pr->features.ts;
    // set key.
    memcpy(chainItem->key, pr->key, KEYLEN);
    // set flow features.
    chainItem->pktCt = 0;

    // append packet features.
    appendRecord(chainItem, pr);

    // set processing state.
    chainItem->inUse = true;
    chainItem->allocAttempt = false; // never tried alloc.
    chainItem->longVectorIdx = 0;
}


void evictMfr(MCLFR *chainItem, MCLFR *evictedMFR) {
    lruEvicts++;
    memcpy(evictedMFR, chainItem, sizeof(MCLFR));
    evictedMFR->pktCt += 1; // Correct packet count, when evict, it represent the last packet ID.
    // If it was previously allocated a partition 2, free it.
    if (chainItem->longVectorIdx != 0) {
        // cout << "freeing long vector ( " << hashVal << ", " << slotId << " )" << endl;
        stackTop++;
        longVectorStack[stackTop] = chainItem->longVectorIdx;
        chainItem->longVectorIdx = 0;
    }
    chainItem->inUse = false;
}

void allocLongPointer(MCLFR *chainItem) {
    if (!chainItem->allocAttempt && (chainItem->pktCt + 1) == partition1Width) {
        chainItem->allocAttempt = true;
        if (stackTop > 0) {
            // cout << "claiming long vector ( " << hashVal << ", " << slotId << " )" << endl;
            // cout << "\tgot long vector index: " << myLongVectorIdx << " from stack pos: " << stackTop << endl;
            chainItem->longVectorIdx = longVectorStack[stackTop];
            stackTop--;
        } else {
            chainItem->longVectorIdx = 0;
        }
    }
}

void appendRecord(MCLFR *chainItem, PacketRecord *pr) {
    chainItem->packetVector[chainItem->pktCt] = pr->features;
    chainItem->th_flags = chainItem->th_flags | pr->th_flags;
    chainItem->lastAccessTs = pr->features.ts;
}

void shortAppend(MCLFR *chainItem, PacketRecord *pr, MCLFR *evictedMFR) {
    // Increment packet id.
    chainItem->pktCt += 1;
    // If pktCt % partition1Width == 0, do a short rollover: export current record, overwrite it.
    if (chainItem->pktCt % partition1Width == 0) {
        memcpy(evictedMFR, chainItem, sizeof(MCLFR));
        chainItem->pktCt = 0;
        exportMfr(evictedMFR);
        shortRollovers++;
    }
    // append the record for this packet.
    appendRecord(chainItem, pr);
}

void longAppend(MCLFR *chainItem, PacketRecord *pr, MCLFR *evictedMFR) {
    // Increment packet id.
    chainItem->pktCt += 1;
    // If pktCt % (partition1Width+partition2Width) == 0, do a long rollover: export current record, overwrite it.
    if (chainItem->pktCt % (partition1Width + partition2Width) == 0) {
        memcpy(evictedMFR, chainItem, sizeof(MCLFR));
        chainItem->pktCt = 0;
        exportMfr(evictedMFR);
        longRollovers++;
    }
    // append the record for this packet.
    appendRecord(chainItem, pr);
}

// convert to export format, increment counters, write to file, etc.
void exportMfr(MCLFR *evictedMFR) {
    if (dump) {
        Export_MCLFR outMclfr{};
        // Copy to packed key.
        memcpy((char *) &outMclfr.packedKey.addrs, evictedMFR->key, 8);
        memcpy((char *) &outMclfr.packedKey.portsproto, evictedMFR->key + 8, 4);
        memcpy((char *) &outMclfr.packedKey.portsproto, evictedMFR->key + 12, 1);

        // Copy flow features.
        outMclfr.flowFeatures.pktCt = (uint32_t) evictedMFR->pktCt;
        outMclfr.flowFeatures.th_flags = evictedMFR->th_flags;

        if (((outMclfr.flowFeatures.th_flags & TH_FIN) == TH_FIN) ||
            ((outMclfr.flowFeatures.th_flags & TH_RST) == TH_RST)) {
            globalFinMfCt++;
        }
        // copy packet features.
        memcpy(outMclfr.packetVector, evictedMFR->packetVector, sizeof(PacketFeatures) * outMclfr.flowFeatures.pktCt);

        // don't store vector.
        // mCLFR_out.push_back(outMclfr);

        // print timestamps..

//        Export_MCLFR t1;
//        Export_MCLFR_hdr t2;
        // cout << "whole struct: " << sizeof(t1) << " hdr: " << sizeof(t2) << " array: " << sizeof(t1.packetVector) << " individual pkt features: " << sizeof(PacketFeatures) * MCLFR_MAXLEN << endl;
        // exit(1);
        // Write to output file.
        if (dump) {
            o.write((char *) &outMclfr.packedKey, sizeof(outMclfr.packedKey));
            o.write((char *) &outMclfr.flowFeatures, sizeof(outMclfr.flowFeatures));
            // Only write the filled features!
            o.write((char *) outMclfr.packetVector, sizeof(PacketFeatures) * outMclfr.flowFeatures.pktCt);
        }
    }
    globalMfCt++;
}


/*=====  End of New stuff  ======*/
