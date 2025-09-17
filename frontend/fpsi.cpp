///////////////////////////

#include "fpsi.h"
#include <unistd.h>
#include <thread>

#include "gm_crypto.h"
#include "fm.h"
#include "fuzzy_mapping.h"
#include "Hamming.h"
// #include "fpsi_bp24.h"

namespace osuCrypto
{
    
/////our protocols///////////    
    void test_our_lp_paillier_fpsi(const CLP& cmd){

        std::cout << "test_our_lp_paillier_fpsi ----------------------------" << std::endl;

        PRNG prng(oc::sysRandomSeed());
        //PRNG prng(block(0,0));

        const u64 dimension = cmd.getOr("d", 2);
        const u64 delta = cmd.getOr("delta", 10);
        const u64 side_length = 1;
        const u64 p = cmd.getOr("p", 2);

        // 读取身份参数：sender / receiver / test(默认)
        std::string role = cmd.getOr("role", std::string("test"));
        if (role != "sender" && role != "receiver" && role != "test") {
            std::cout << "Unknown role: " << role << ". Use -role sender|receiver|test" << std::endl;
            return;
        }

        std::cout << "role         : " << role << std::endl;

        // 获取文件路径参数（只在对应角色需要时校验）
        std::string receiver_file = cmd.getOr("rf", std::string(""));
        std::string sender_file   = cmd.getOr("sf", std::string(""));
        std::string result_file   = cmd.getOr("if", std::string(""));

        // 校验文件参数
        if ((role == "receiver" || role == "test") && receiver_file.empty()) {
            std::cout << "Error: Receiver file path not provided! Usage: -rf <receiver.txt>" << std::endl;
            return;
        }
        if ((role == "sender" || role == "test") && sender_file.empty()) {
            std::cout << "Error: Sender file path not provided! Usage: -sf <sender.txt>" << std::endl;
            return;
        }

        // 只读取本端需要的文件数据
        std::vector<std::vector<u64>> receiver_elements;
        std::vector<std::vector<u64>> sender_elements;
        u64 recv_set_size = 0;
        u64 send_set_size = 0;

        if (role == "receiver" || role == "test") {
            std::ifstream recv_ifs(receiver_file);
            if (!recv_ifs.is_open()) {
                std::cout << "Error: Unable to open receiver file: " << receiver_file << std::endl;
                return;
            }
            std::string recv_line;
            while (std::getline(recv_ifs, recv_line)) {
                std::istringstream iss(recv_line);
                std::vector<u64> point;
                u64 value;
                while (iss >> value) point.push_back(value);
                if (point.size() != dimension) {
                    std::cout << "Error: Dimension mismatch in receiver file!" << std::endl;
                    return;
                }
                receiver_elements.push_back(std::move(point));
            }
            recv_ifs.close();
            recv_set_size = receiver_elements.size();
            std::cout << "recv_set_size: " << recv_set_size << std::endl;
        }

        if (role == "sender" || role == "test") {
            std::ifstream send_ifs(sender_file);
            if (!send_ifs.is_open()) {
                std::cout << "Error: Unable to open sender file: " << sender_file << std::endl;
                return;
            }
            std::string send_line;
            while (std::getline(send_ifs, send_line)) {
                std::istringstream iss(send_line);
                std::vector<u64> point;
                u64 value;
                while (iss >> value) point.push_back(value);
                if (point.size() != dimension) {
                    std::cout << "Error: Dimension mismatch in sender file!" << std::endl;
                    return;
                }
                sender_elements.push_back(std::move(point));
            }
            send_ifs.close();
            send_set_size = sender_elements.size();
            std::cout << "send_set_size: " << send_set_size << std::endl;
        }

        std::cout << "dimension    : " << dimension << std::endl;
        std::cout << "delta        : " << delta << std::endl;
        std::cout << "distance     : l_" << p << std::endl;
        std::cout << "data init done" << std::endl;

        ///////////////////////////////////////////////////////////////////////////////////////
        // key generate 
        Rist25519_number recv_sk(prng);
        std::array<Rist25519_point, 2> recv_pk;
        

        Rist25519_number send_sk(prng);
        std::array<Rist25519_point, 2> send_pk;
        

        if (role == "receiver" || role == "test") {
            recv_pk[0] = Rist25519_point(prng);
            recv_pk[1] = recv_sk * recv_pk[0];
        }
        if (role == "sender" || role == "test") {
            send_pk[0] = Rist25519_point(prng);
            send_pk[1] = send_sk * send_pk[0];
        }
        

        Rist25519_number recv_dh_sk(prng);
        Rist25519_number send_dh_sk(prng);

        ipcl::initializeContext("QAT");
        // ipcl::KeyPair paillier_key = ipcl::generateKeypair(2048, true);

        // // 初始化 KeyPair
        // ipcl::KeyPair paillier_key;

        // BigNumber nn;
        // BigNumber pp("0x87728f9fd1f0da1af7ae6d940afe29dc4f8f0dbc0343198e5321981186235a9f2061b5e76a026afb4966737da6ebe756f626af5d23c24c2d45b336df9d3f91b0319120033b9d773296be3f08731fb8ba2460276d5d64f67a4290963ea2c4c66baefacef6c11f2970bfb2884f27c0af3e1ef909f5b111ccec38166345bfbc09f3");
        // BigNumber qq("0xf34f2587d81441e0df353a0530c42da89dfa209564fdb1597900896b388c4c07f3308aff861fb91fc8d3c3c711117d3db440f02c6ea75563f40c7658917c1fbb1fc192d2b9fe93b28511839c8805a53abcfeb791754bf01ee939d71a106521b57b276927ef453a1bcefc53026c89b3cb25a7e5860ae01e7dad28f68c453ef747");
        // nn = pp * qq;
        // // 创建公钥（使用2048位模数，不启用DJN模式）
        // ipcl::PublicKey pub_key(nn, 2048, true);

        // // 创建私钥（使用公钥和素数p、q）
        // ipcl::PrivateKey priv_key(pub_key, pp, qq);

        // // 组合成 KeyPair
        // paillier_key.pub_key = pub_key;
        // paillier_key.priv_key = priv_key;

        ipcl::setHybridMode(ipcl::HybridMode::OPTIMAL);

        DH25519_number recv_dh_k(prng);
        DH25519_number send_dh_k(prng);

        Timer time;
        time.setTimePoint("Start");

        ///////////////////////////////////////////////////////////////////////////////////////
        // offline - 只计算当前角色需要的部分
        std::vector<std::vector<Rist25519_number>> recv_values;
        std::vector<std::vector<Rist25519_number>> send_values;
        std::stack<Rist25519_number> recv_vals_candidate_r;
        std::stack<Rist25519_number> recv_vals_candidate_skr;
        std::stack<Rist25519_number> send_vals_candidate_r;
        std::stack<Rist25519_number> send_vals_candidate_skr;

        if (role == "receiver" || role == "test") {
            fmap::assign_segments(recv_set_size, recv_values, recv_vals_candidate_r, recv_vals_candidate_skr, dimension, delta, side_length, recv_sk);
        }
        if (role == "sender" || role == "test") {
            fmap::assign_segments(send_set_size, send_values, send_vals_candidate_r, send_vals_candidate_skr, dimension, delta, side_length, send_sk);
        }

        std::vector<Rist25519_number> recv_masks, recv_masks_inv;
        std::vector<Rist25519_number> send_masks, send_masks_inv;

        if (role == "receiver" || role == "test") {
            fmap::get_mask_cipher(recv_set_size, recv_masks, recv_masks_inv, recv_pk);
        }
        if (role == "sender" || role == "test") {
            fmap::get_mask_cipher(send_set_size, send_masks, send_masks_inv, send_pk);
        }
        std::cout << "fmap offline done" << std::endl;

        // fmat / sender masks etc.
        std::vector<std::vector<block>> fmat_vals;

        std::vector<u32> masks;
        ipcl::CipherText vec_mask_ct;
        std::vector<std::vector<block>> send_prefixes;
        std::vector<std::vector<DH25519_point>> send_prefixes_k;
        u64 max_prefix_num = 0;
        std::vector<DH25519_point> send_prefixes_k_net;

        if (role == "receiver") {
            std::string ip = cmd.getOr("ip",std::string("127.0.0.1:1234"));
            auto socket = macoro::sync_wait(coproto::AsioConnect(ip, coproto::global_io_context()));
            ipcl::KeyPair paillier_key = ipcl::generateKeypair(2048, true);
            BigNumber nn;
            nn = *(paillier_key.pub_key.getN());
            std::string n_str;
            nn.num2hex(n_str);
            coproto::sync_wait(socket.send(n_str));
            fm_paillier::receiver_value_paillier_lp(recv_set_size, fmat_vals, dimension, delta, p, paillier_key);    

            std::vector<Rist25519_point> recv_vec_dhkk_seedsum(recv_set_size);

            std::thread thread_fmap_recv(
                fmap::fmap_recv_online,
                &socket,
                &receiver_elements,
                &recv_values,
                &recv_vals_candidate_r, &recv_vals_candidate_skr,
                &recv_masks, &recv_masks_inv,
                &recv_vec_dhkk_seedsum,
                dimension, delta, side_length,
                recv_sk, recv_pk, recv_dh_sk
            );
            thread_fmap_recv.join();

            std::cout << "fmap online done" << std::endl;
            time.setTimePoint("fmap done");

            std::thread thread_fmat_recv(
                fm_paillier::fmat_paillier_recv_online,
                &socket,
                &receiver_elements, &recv_vec_dhkk_seedsum,
                &fmat_vals,
                dimension, delta, p,
                paillier_key, recv_dh_k,
                result_file
            );
            thread_fmat_recv.join();

            time.setTimePoint("fmat done");
            time.setTimePoint("online done");
            ipcl::setHybridOff();
            ipcl::terminateContext();

            std::cout << (time) << std::endl;

            auto recv_bytes_present = socket.bytesSent();
            auto recv_bytes_received = socket.bytesReceived();
            std::cout << "[our_lp] recv sends:  "<< (recv_bytes_present) / 1024.0 / 1024 << "MB" << std::endl;
            std::cout << "[our_lp] recv receives:  "<< (recv_bytes_received) / 1024.0 / 1024 << "MB" << std::endl;
        }

        else if (role == "sender") {
            std::string ip = cmd.getOr("ip",std::string("127.0.0.1:1234"));
            auto socket = macoro::sync_wait(coproto::AsioAcceptor(ip, coproto::global_io_context()).accept());
            std::string n_str;
            coproto::sync_wait(socket.recvResize(n_str));
            BigNumber nn(n_str.c_str());
            ipcl::PublicKey send_pubkey(nn,2048,true);
            fm_paillier::sender_mask_paillier_lp(send_set_size, masks, vec_mask_ct, send_pubkey);
            max_prefix_num = fm_paillier::sender_get_prefixes(masks, send_prefixes, delta, p);
            fm_paillier::prefixes_pow_sk(send_prefixes, send_prefixes_k, send_dh_k);
            fm_paillier::pad_send_prefixes_k(send_prefixes_k, send_prefixes_k_net, max_prefix_num);

            std::vector<Rist25519_point> send_vec_dhkk_seedsum(send_set_size);

            std::cout << "fmap online begin" << std::endl;
            time.setTimePoint("fmap online begin");

            std::thread thread_fmap_send(
                fmap::fmap_send_online,
                &socket,
                &sender_elements,
                &send_values,
                &send_vals_candidate_r, &send_vals_candidate_skr,
                &send_masks, &send_masks_inv,
                &send_vec_dhkk_seedsum,
                dimension, delta, side_length,
                send_sk, send_pk, send_dh_sk
            );
            thread_fmap_send.join();

            std::cout << "fmap online done" << std::endl;
            time.setTimePoint("fmap done");

            std::thread thread_fmat_send(
                fm_paillier::fmat_paillier_send_online,
                &socket,
                &sender_elements, &send_vec_dhkk_seedsum,
                &send_prefixes_k_net, &vec_mask_ct,
                dimension, delta, p,
                send_pubkey, send_dh_k
            );
            thread_fmat_send.join();

            time.setTimePoint("fmat done");
            time.setTimePoint("online done");
            ipcl::setHybridOff();
            ipcl::terminateContext();

            std::cout << (time) << std::endl;

            auto send_bytes_present = socket.bytesSent();
            auto send_bytes_received = socket.bytesReceived();
            std::cout << "[our_lp] send sends:  "<< (send_bytes_present) / 1024.0 / 1024 << "MB" << std::endl;
            std::cout << "[our_lp] send receives:  "<< (send_bytes_received) / 1024.0 / 1024 << "MB" << std::endl;
        }
        else { // 本地测试
            ipcl::KeyPair paillier_key = ipcl::generateKeypair(2048, true);

            fm_paillier::receiver_value_paillier_lp(recv_set_size, fmat_vals, dimension, delta, p, paillier_key);
            fm_paillier::sender_mask_paillier_lp(send_set_size, masks, vec_mask_ct, paillier_key.pub_key);
            max_prefix_num = fm_paillier::sender_get_prefixes(masks, send_prefixes, delta, p);
            fm_paillier::prefixes_pow_sk(send_prefixes, send_prefixes_k, send_dh_k);
            fm_paillier::pad_send_prefixes_k(send_prefixes_k, send_prefixes_k_net, max_prefix_num);

            auto sockets = coproto::LocalAsyncSocket::makePair();

            std::vector<Rist25519_point> recv_vec_dhkk_seedsum(recv_set_size);
            std::vector<Rist25519_point> send_vec_dhkk_seedsum(send_set_size);

            std::cout << "fmap online begin" << std::endl;

            std::thread thread_fmap_recv(
                fmap::fmap_recv_online,
                &sockets[0],
                &receiver_elements,
                &recv_values,
                &recv_vals_candidate_r, &recv_vals_candidate_skr,
                &recv_masks, &recv_masks_inv,
                &recv_vec_dhkk_seedsum,
                dimension, delta, side_length,
                recv_sk, recv_pk, recv_dh_sk
            );
            std::thread thread_fmap_send(
                fmap::fmap_send_online,
                &sockets[1],
                &sender_elements,
                &send_values,
                &send_vals_candidate_r, &send_vals_candidate_skr,
                &send_masks, &send_masks_inv,
                &send_vec_dhkk_seedsum,
                dimension, delta, side_length,
                send_sk, send_pk, send_dh_sk
            );
            thread_fmap_recv.join();
            thread_fmap_send.join();

            std::cout << "fmap online done" << std::endl;
            time.setTimePoint("fmap done");

            std::thread thread_fmat_recv(
                fm_paillier::fmat_paillier_recv_online,
                &sockets[0],
                &receiver_elements, &recv_vec_dhkk_seedsum,
                &fmat_vals,
                dimension, delta, p,
                paillier_key, recv_dh_k,
                result_file
            );
            std::thread thread_fmat_send(
                fm_paillier::fmat_paillier_send_online,
                &sockets[1],
                &sender_elements, &send_vec_dhkk_seedsum,
                &send_prefixes_k_net, &vec_mask_ct,
                dimension, delta, p,
                paillier_key.pub_key, send_dh_k
            );
            thread_fmat_recv.join();
            thread_fmat_send.join();

            time.setTimePoint("fmat done");
            time.setTimePoint("online done");
            ipcl::setHybridOff();
            ipcl::terminateContext();

            std::cout << (time) << std::endl;  
            auto recv_bytes_present = sockets[0].bytesSent();
            auto send_bytes_present = sockets[1].bytesSent();

            std::cout << "[our_lp] recv sends:  "<< (recv_bytes_present) / 1024.0 / 1024 << "MB" << std::endl;
            std::cout << "[our_lp] send sends:  "<< (send_bytes_present) / 1024.0 / 1024 << "MB" << std::endl;
            std::cout << "[our_lp] comm total:  "<< ((recv_bytes_present) + (send_bytes_present)) / 1024.0 / 1024 << "MB" << std::endl;
        
        }
        
        std::cout << std::endl;

        const bool out_to_file = cmd.isSet("file");
        if(out_to_file){
            std::string filename = "test_our_lp_paillier_fpsi_m_"+std::to_string(send_set_size)
                                    +"_n_"+std::to_string(recv_set_size)
                                    +"_d_"+std::to_string(dimension)
                                    +"_delta_"+std::to_string(delta)
                                    +"_p_"+std::to_string(p)+".txt";
            std::ofstream mycout(filename, std::ios::app);
            mycout << std::endl << "test_our_lp_paillier_fpsi ----------------------------" << std::endl;
            mycout << "role         : " << role << std::endl;
            mycout << "recv_set_size: " << recv_set_size << std::endl;
            mycout << "send_set_size: " << send_set_size << std::endl;
            mycout << "dimension:     " << dimension << std::endl;
            mycout << "delta:         " << delta << std::endl;
            mycout << "l_p:           " << p << std::endl;
            //mycout << "[our_lp] recv sends:  "<< (recv_bytes_present) / 1024.0 / 1024 << "MB" << std::endl;
            //mycout << "[our_lp] send sends:  "<< (send_bytes_present) / 1024.0 / 1024 << "MB" << std::endl;
            //mycout << "[our_lp] comm total:  "<< ((recv_bytes_present) + (send_bytes_present)) / 1024.0 / 1024 << "MB" << std::endl;
            mycout << time << std::endl << std::endl;
            mycout.close();
        }
        return;
    }

    void test_our_linfty_paillier_fpsi(const CLP& cmd) {
        std::cout << "test_our_linfty_paillier_fpsi ----------------------------" << std::endl;

        PRNG prng(oc::sysRandomSeed());

        const u64 dimension = cmd.getOr("d", 2);
        const u64 delta = cmd.getOr("delta", 10);
        const u64 side_length = 1;
        const u64 p = cmd.getOr("p", 2);

        // 读取身份参数：sender / receiver / test(默认)
        std::string role = cmd.getOr("role", std::string("test"));
        if (role != "sender" && role != "receiver" && role != "test") {
            std::cout << "Unknown role: " << role << ". Use -role sender|receiver|test" << std::endl;
            return;
        }

        std::cout << "role         : " << role << std::endl;

        // 获取文件路径参数（只在对应角色需要时校验）
        std::string receiver_file = cmd.getOr("rf", std::string(""));
        std::string sender_file   = cmd.getOr("sf", std::string(""));
        std::string result_file   = cmd.getOr("if", std::string(""));

        // 校验文件参数
        if ((role == "receiver" || role == "test") && receiver_file.empty()) {
            std::cout << "Error: Receiver file path not provided! Usage: -rf <receiver.txt>" << std::endl;
            return;
        }
        if ((role == "sender" || role == "test") && sender_file.empty()) {
            std::cout << "Error: Sender file path not provided! Usage: -sf <sender.txt>" << std::endl;
            return;
        }

        // 只读取本端需要的文件数据
        std::vector<std::vector<u64>> receiver_elements;
        std::vector<std::vector<u64>> sender_elements;
        u64 recv_set_size = 0;
        u64 send_set_size = 0;

        if (role == "receiver" || role == "test") {
            std::ifstream recv_ifs(receiver_file);
            if (!recv_ifs.is_open()) {
                std::cout << "Error: Unable to open receiver file: " << receiver_file << std::endl;
                return;
            }
            std::string recv_line;
            while (std::getline(recv_ifs, recv_line)) {
                std::istringstream iss(recv_line);
                std::vector<u64> point;
                u64 value;
                while (iss >> value) point.push_back(value);
                if (point.size() != dimension) {
                    std::cout << "Error: Dimension mismatch in receiver file!" << std::endl;
                    return;
                }
                receiver_elements.push_back(std::move(point));
            }
            recv_ifs.close();
            recv_set_size = receiver_elements.size();
            std::cout << "recv_set_size: " << recv_set_size << std::endl;
        }

        if (role == "sender" || role == "test") {
            std::ifstream send_ifs(sender_file);
            if (!send_ifs.is_open()) {
                std::cout << "Error: Unable to open sender file: " << sender_file << std::endl;
                return;
            }
            std::string send_line;
            while (std::getline(send_ifs, send_line)) {
                std::istringstream iss(send_line);
                std::vector<u64> point;
                u64 value;
                while (iss >> value) point.push_back(value);
                if (point.size() != dimension) {
                    std::cout << "Error: Dimension mismatch in sender file!" << std::endl;
                    return;
                }
                sender_elements.push_back(std::move(point));
            }
            send_ifs.close();
            send_set_size = sender_elements.size();
            std::cout << "send_set_size: " << send_set_size << std::endl;
        }

        std::cout << "dimension    : " << dimension << std::endl;
        std::cout << "delta        : " << delta << std::endl;
        std::cout << "distance     : l_infty" << std::endl;
        std::cout << "data init done" << std::endl;

        ///////////////////////////////////////////////////////////////////////////////////////
        // key generate 
        Rist25519_number recv_sk(prng);
        std::array<Rist25519_point, 2> recv_pk;
        
        Rist25519_number send_sk(prng);
        std::array<Rist25519_point, 2> send_pk;
        
        if (role == "receiver" || role == "test") {
            recv_pk[0] = Rist25519_point(prng);
            recv_pk[1] = recv_sk * recv_pk[0];
        }
        if (role == "sender" || role == "test") {
            send_pk[0] = Rist25519_point(prng);
            send_pk[1] = send_sk * send_pk[0];
        }
        
        Rist25519_number recv_dh_sk(prng);
        Rist25519_number send_dh_sk(prng);

        ipcl::initializeContext("QAT");
        ipcl::setHybridMode(ipcl::HybridMode::OPTIMAL);

        Timer time;
        time.setTimePoint("Start");

        ///////////////////////////////////////////////////////////////////////////////////////
        // offline - 只计算当前角色需要的部分
        std::vector<std::vector<Rist25519_number>> recv_values;
        std::vector<std::vector<Rist25519_number>> send_values;
        std::stack<Rist25519_number> recv_vals_candidate_r;
        std::stack<Rist25519_number> recv_vals_candidate_skr;
        std::stack<Rist25519_number> send_vals_candidate_r;
        std::stack<Rist25519_number> send_vals_candidate_skr;

        if (role == "receiver" || role == "test") {
            fmap::assign_segments(recv_set_size, recv_values, recv_vals_candidate_r, recv_vals_candidate_skr, dimension, delta, side_length, recv_sk);
        }
        if (role == "sender" || role == "test") {
            fmap::assign_segments(send_set_size, send_values, send_vals_candidate_r, send_vals_candidate_skr, dimension, delta, side_length, send_sk);
        }

        std::vector<Rist25519_number> recv_masks, recv_masks_inv;
        std::vector<Rist25519_number> send_masks, send_masks_inv;

        if (role == "receiver" || role == "test") {
            fmap::get_mask_cipher(recv_set_size, recv_masks, recv_masks_inv, recv_pk);
        }
        if (role == "sender" || role == "test") {
            fmap::get_mask_cipher(send_set_size, send_masks, send_masks_inv, send_pk);
        }
        std::cout << "fmap offline done" << std::endl;

        // fmat相关数据
        std::vector<std::vector<block>> fmat_vals;

        time.setTimePoint("offline");

        if (role == "receiver") {
            std::string ip = cmd.getOr("ip", std::string("127.0.0.1:1234"));
            auto socket = macoro::sync_wait(coproto::AsioConnect(ip, coproto::global_io_context()));
            ipcl::KeyPair paillier_key = ipcl::generateKeypair(2048, true);
            fm_paillier::receiver_value_paillier_linfty(recv_set_size, fmat_vals, dimension, delta, paillier_key);
            
            // 发送公钥
            BigNumber nn = *(paillier_key.pub_key.getN());
            std::string n_str;
            nn.num2hex(n_str);
            coproto::sync_wait(socket.send(n_str));

            std::vector<Rist25519_point> recv_vec_dhkk_seedsum(recv_set_size);

            std::thread thread_fmap_recv(
                fmap::fmap_recv_online,
                &socket,
                &receiver_elements,
                &recv_values,
                &recv_vals_candidate_r, &recv_vals_candidate_skr,
                &recv_masks, &recv_masks_inv,
                &recv_vec_dhkk_seedsum,
                dimension, delta, side_length,
                recv_sk, recv_pk, recv_dh_sk
            );
            thread_fmap_recv.join();

            std::cout << "fmap online done" << std::endl;
            time.setTimePoint("fmap done");

            std::thread thread_fmat_recv(
                fm_paillier::fmat_paillier_linfty_recv_online,
                &socket,
                &receiver_elements, &recv_vec_dhkk_seedsum,
                &fmat_vals,
                dimension, delta,
                paillier_key, result_file
            );
            thread_fmat_recv.join();

            time.setTimePoint("fmat done");
            time.setTimePoint("online done");
            ipcl::setHybridOff();
            ipcl::terminateContext();

            std::cout << (time) << std::endl;

            auto recv_bytes_present = socket.bytesSent();
            auto recv_bytes_received = socket.bytesReceived();
            std::cout << "[our_linfty] recv sends:  " << (recv_bytes_present) / 1024.0 / 1024 << "MB" << std::endl;
            std::cout << "[our_linfty] recv receives:  " << (recv_bytes_received) / 1024.0 / 1024 << "MB" << std::endl;
        } else if (role == "sender") {
            std::string ip = cmd.getOr("ip", std::string("127.0.0.1:1234"));
            auto socket = macoro::sync_wait(coproto::AsioAcceptor(ip, coproto::global_io_context()).accept());
            
            // 接收公钥
            std::string n_str;
            coproto::sync_wait(socket.recvResize(n_str));
            BigNumber nn(n_str.c_str());
            ipcl::PublicKey send_pubkey(nn, 2048, true);

            std::vector<Rist25519_point> send_vec_dhkk_seedsum(send_set_size);

            std::cout << "fmap online begin" << std::endl;
            time.setTimePoint("fmap online begin");

            std::thread thread_fmap_send(
                fmap::fmap_send_online,
                &socket,
                &sender_elements,
                &send_values,
                &send_vals_candidate_r, &send_vals_candidate_skr,
                &send_masks, &send_masks_inv,
                &send_vec_dhkk_seedsum,
                dimension, delta, side_length,
                send_sk, send_pk, send_dh_sk
            );
            thread_fmap_send.join();

            std::cout << "fmap online done" << std::endl;
            time.setTimePoint("fmap done");

            std::thread thread_fmat_send(
                fm_paillier::fmat_paillier_linfty_send_online,
                &socket,
                &sender_elements, &send_vec_dhkk_seedsum,
                dimension, delta,
                send_pubkey
            );
            thread_fmat_send.join();

            time.setTimePoint("fmat done");
            time.setTimePoint("online done");
            ipcl::setHybridOff();
            ipcl::terminateContext();

            std::cout << (time) << std::endl;

            auto send_bytes_present = socket.bytesSent();
            auto send_bytes_received = socket.bytesReceived();
            std::cout << "[our_linfty] send sends:  " << (send_bytes_present) / 1024.0 / 1024 << "MB" << std::endl;
            std::cout << "[our_linfty] send receives:  " << (send_bytes_received) / 1024.0 / 1024 << "MB" << std::endl;
        } else { // 本地测试
            ipcl::KeyPair paillier_key = ipcl::generateKeypair(2048, true);
            fm_paillier::receiver_value_paillier_linfty(recv_set_size, fmat_vals, dimension, delta, paillier_key);

            auto sockets = coproto::LocalAsyncSocket::makePair();

            std::vector<Rist25519_point> recv_vec_dhkk_seedsum(recv_set_size);
            std::vector<Rist25519_point> send_vec_dhkk_seedsum(send_set_size);

            std::cout << "fmap online begin" << std::endl;

            std::thread thread_fmap_recv(
                fmap::fmap_recv_online,
                &sockets[0],
                &receiver_elements,
                &recv_values,
                &recv_vals_candidate_r, &recv_vals_candidate_skr,
                &recv_masks, &recv_masks_inv,
                &recv_vec_dhkk_seedsum,
                dimension, delta, side_length,
                recv_sk, recv_pk, recv_dh_sk
            );
            std::thread thread_fmap_send(
                fmap::fmap_send_online,
                &sockets[1],
                &sender_elements,
                &send_values,
                &send_vals_candidate_r, &send_vals_candidate_skr,
                &send_masks, &send_masks_inv,
                &send_vec_dhkk_seedsum,
                dimension, delta, side_length,
                send_sk, send_pk, send_dh_sk
            );
            thread_fmap_recv.join();
            thread_fmap_send.join();

            std::cout << "fmap online done" << std::endl;
            time.setTimePoint("fmap done");

            std::thread thread_fmat_recv(
                fm_paillier::fmat_paillier_linfty_recv_online,
                &sockets[0],
                &receiver_elements, &recv_vec_dhkk_seedsum,
                &fmat_vals,
                dimension, delta,
                paillier_key, result_file
            );
            std::thread thread_fmat_send(
                fm_paillier::fmat_paillier_linfty_send_online,
                &sockets[1],
                &sender_elements, &send_vec_dhkk_seedsum,
                dimension, delta,
                paillier_key.pub_key
            );
            thread_fmat_recv.join();
            thread_fmat_send.join();

            time.setTimePoint("fmat done");
            time.setTimePoint("online done");
            ipcl::setHybridOff();
            ipcl::terminateContext();

            std::cout << (time) << std::endl;

            auto recv_bytes_present = sockets[0].bytesSent();
            auto send_bytes_present = sockets[1].bytesSent();

            std::cout << "[our_linfty] recv sends:  " << (recv_bytes_present) / 1024.0 / 1024 << "MB" << std::endl;
            std::cout << "[our_linfty] send sends:  " << (send_bytes_present) / 1024.0 / 1024 << "MB" << std::endl;
            std::cout << "[our_linfty] comm total:  " << ((recv_bytes_present) + (send_bytes_present)) / 1024.0 / 1024 << "MB" << std::endl;
        }

        std::cout << std::endl;

        const bool out_to_file = cmd.isSet("file");
        if (out_to_file) {
            std::string filename = "test_our_linfty_paillier_fpsi_m_" + std::to_string(send_set_size)
                + "_n_" + std::to_string(recv_set_size)
                + "_d_" + std::to_string(dimension)
                + "_delta_" + std::to_string(delta)
                + "_p_infty" + ".txt";
            std::ofstream mycout(filename, std::ios::app);
            mycout << std::endl << "test_our_linfty_paillier_fpsi ----------------------------" << std::endl;
            mycout << "role         : " << role << std::endl;
            mycout << "recv_set_size: " << recv_set_size << std::endl;
            mycout << "send_set_size: " << send_set_size << std::endl;
            mycout << "dimension:     " << dimension << std::endl;
            mycout << "delta:         " << delta << std::endl;
            mycout << "distance:      l_infty" << std::endl;
            mycout << time << std::endl << std::endl;
            mycout.close();
        }

        return;
    }

void test_gm_fpsi_hamming(const CLP& cmd) {
    std::cout << "test_gm_fpsi_hamming ----------------------------" << std::endl;
    PRNG prng(oc::sysRandomSeed());

    const u64 dimension = cmd.getOr("hamd", 128);
    const u64 delta = cmd.getOr("hamdelta", 4);
    const u64 side_length = cmd.getOr("hamside", ((dimension / (delta + 1)) / 8) * 8);
    std::string result_file = cmd.getOr("if", std::string(""));

    // 读取身份参数：sender / receiver / test(默认)
    std::string role = cmd.getOr("role", std::string("test"));
    if (role != "sender" && role != "receiver" && role != "test") {
        std::cout << "Unknown role: " << role << ". Use -role sender|receiver|test" << std::endl;
        return;
    }

    std::cout << "role         : " << role << std::endl;

    // 获取文件路径参数（只在对应角色需要时校验）
    std::string receiver_file = cmd.getOr("rf", std::string(""));
    std::string sender_file = cmd.getOr("sf", std::string(""));

    // 校验文件参数
    if ((role == "receiver" || role == "test") && receiver_file.empty()) {
        std::cout << "Error: Receiver file path not provided! Usage: -rf <receiver.txt>" << std::endl;
        return;
    }
    if ((role == "sender" || role == "test") && sender_file.empty()) {
        std::cout << "Error: Sender file path not provided! Usage: -sf <sender.txt>" << std::endl;
        return;
    }

    // 只读取本端需要的文件数据
    std::vector<BitVector> receiver_set;
    std::vector<BitVector> sender_set;
    u64 recv_set_size = 0;
    u64 send_set_size = 0;

    if (role == "receiver" || role == "test") {
        std::ifstream recv_stream(receiver_file);
        if (!recv_stream.is_open()) {
            std::cout << "Error: Unable to open receiver file: " << receiver_file << std::endl;
            return;
        }
        
        std::string line;
        while (std::getline(recv_stream, line)) {
            if (line.empty()) continue;
            
            // 移除行尾的换行符和空白字符
            line.erase(std::remove_if(line.begin(), line.end(), ::isspace), line.end());
            
            // 检查字符串长度是否为dimension
            if (line.length() != dimension) {
                printf("Line length %zu does not match dimension %lu: %s\n", line.length(), dimension, line.c_str());
                return;
            }
            
            // 检查字符串是否只包含0和1
            if (line.find_first_not_of("01") != std::string::npos) {
                printf("Line contains non-binary characters: %s\n", line.c_str());
                return;
            }
            
            // 将字符串转换为BitVector
            BitVector bv(dimension);
            for (u64 i = 0; i < dimension; ++i) {
                bv[i] = (line[i] == '1');
            }
            
            receiver_set.push_back(bv);
        }
       
        recv_set_size = receiver_set.size();
        std::cout << "recv_set_size: " << recv_set_size << std::endl;
    }

    if (role == "sender" || role == "test") {
        std::ifstream send_stream(sender_file);
        if (!send_stream.is_open()) {
            std::cout << "Error: Unable to open sender file: " << sender_file << std::endl;
            return;
        }
        
        std::string line;
        while (std::getline(send_stream, line)) {
            if (line.empty()) continue;
            
            // 移除行尾的换行符和空白字符
            line.erase(std::remove_if(line.begin(), line.end(), ::isspace), line.end());
            
            // 检查字符串长度是否为dimension
            if (line.length() != dimension) {
                printf("Line length %zu does not match dimension %lu: %s\n", line.length(), dimension, line.c_str());
                return;
            }
            
            // 检查字符串是否只包含0和1
            if (line.find_first_not_of("01") != std::string::npos) {
                printf("Line contains non-binary characters: %s\n", line.c_str());
                return;
            }
            
            // 将字符串转换为BitVector
            BitVector bv(dimension);
            for (u64 i = 0; i < dimension; ++i) {
                bv[i] = (line[i] == '1');
            }
            
            sender_set.push_back(bv);
        }
        send_set_size = sender_set.size();
        std::cout << "send_set_size: " << send_set_size << std::endl;
    }

    std::cout << "dimension    : " << dimension << std::endl;
    std::cout << "delta        : " << delta << std::endl;
    std::cout << "side_length  : " << side_length << std::endl;

    // 参数检查
    if ((side_length == 0)) {
        printf("dimension should not be less than (threshold + 1) * 8\n");
        return;
    }
    if ((side_length > ((dimension / (delta + 1)) / 8) * 8)) {
        printf("side_length should be less than ((dimension / (threshold + 1)) / 8) * 8\n");
        return;
    }
    if ((side_length % 8 != 0)) {
        printf("side_length mod 8 should be 0\n");
        return;
    }
    if (role == "receiver" || role == "test") {
        if ((pow(2, side_length) <= recv_set_size)) {
            printf("pow(2, side_length) should be greater than recv_set_size\n");
            return;
        }
    }

    // 计算unique_components（仅接收方需要）
    std::vector<std::vector<u64>> unique_components;
    if (role == "receiver" || role == "test") {
        unique_components.resize(recv_set_size);
        // 计算块的数量
        u64 num_blocks = dimension / side_length;
        if (dimension % side_length != 0) {
            num_blocks++;
        }

        // 将每个BitVector转换为u64类型的向量
        std::vector<std::vector<u64>> recv_real_set(recv_set_size, std::vector<u64>(num_blocks, 0));

        for (u64 i = 0; i < recv_set_size; i++) {
            for (u64 j = 0; j < num_blocks; j++) {
                u64 start_idx = j * side_length;
                u64 end_idx = std::min((j + 1) * side_length, dimension);
                u64 block_value = 0;
                
                // 将side_length位的块转换为u64整数
                for (u64 k = start_idx; k < end_idx; k++) {
                    block_value = (block_value << 1) | (receiver_set[i][k] ? 1 : 0);
                }
                
                recv_real_set[i][j] = block_value;
            }
        }

        // 计算unique_components
        for (u64 i = 0; i < recv_set_size; i++) {
            for (u64 j = 0; j < num_blocks; j++) {
                bool unique = true;
                for (u64 k = 0; k < recv_set_size; k++) {
                    if (k == i) continue;
                    if (recv_real_set[i][j] == recv_real_set[k][j]) {
                        unique = false;
                        break;
                    }
                }
                if (unique) {
                    unique_components[i].push_back(j);
                    // 如果已经找到delta+1个唯一分量，提前退出内层循环
                    if (unique_components[i].size() >= delta + 1) {
                        break;
                    }
                }
            }
            // 检查unique_components[i]的大小是否不超过delta+1
            if (unique_components[i].size() < delta + 1) {
                printf("recv_set is not independent: no enough unique components at index %lu\n", i);
                return;
            }
        }
    }

    pubkey_t pbkey;
    privkey_t prkey;

    mpz_init(pbkey.a);
    mpz_init(pbkey.N);
    mpz_init(prkey.p);
    mpz_init(prkey.q);

    // 密钥生成
    if (role == "receiver" || role == "test") {
        gen_keys(&pbkey, &prkey);
    }

    Timer time;
    time.setTimePoint("Start");
    std::cout << "Start" << std::endl;

    // 离线预计算
    std::stack<std::array<std::vector<element>, 2UL>> pre_vals;
    std::stack<BitVector> masks;
    std::stack<std::vector<std::vector<block>>> masks_ciphers_block;


    time.setTimePoint("Offline done");
    std::cout << "offline done" << std::endl;

    if (role == "receiver") {
        Hamming::receiver_precomp_value_hamming(recv_set_size, pre_vals, dimension, delta, &pbkey);
        std::string ip = cmd.getOr("ip", std::string("127.0.0.1:1234"));
        auto socket = macoro::sync_wait(coproto::AsioAcceptor(ip, coproto::global_io_context()).accept());
        
        // 发送公钥给发送方
        std::string N_str = mpz_get_str(NULL, 10, pbkey.N);
        std::string a_str = mpz_get_str(NULL, 10, pbkey.a);
        coproto::sync_wait(socket.send(N_str));
        coproto::sync_wait(socket.send(a_str));

        Hamming::fpsi_hamming_recv_online(
            &socket,
            &receiver_set, &unique_components,
            &pre_vals,
            dimension, delta, side_length,
            &pbkey, &prkey, result_file
        );

        time.setTimePoint("online done");
        time.setTimePoint("fpsi done");

        std::cout << (time) << std::endl;

        auto recv_bytes_present = socket.bytesSent();
        auto recv_bytes_received = socket.bytesReceived();
        std::cout << "[fpsi_hamming] recv sends:  " << (recv_bytes_present) / 1024.0 / 1024 << "MB" << std::endl;
        std::cout << "[fpsi_hamming] recv receives:  " << (recv_bytes_received) / 1024.0 / 1024 << "MB" << std::endl;
    } else if (role == "sender") {
        std::string ip = cmd.getOr("ip", std::string("127.0.0.1:1234"));
        auto socket = macoro::sync_wait(coproto::AsioConnect(ip, coproto::global_io_context()));
        
        // 接收公钥
        std::string N_str, a_str;
        coproto::sync_wait(socket.recvResize(N_str));
        coproto::sync_wait(socket.recvResize(a_str));
        
        mpz_set_str(pbkey.N, N_str.c_str(), 10);
        mpz_set_str(pbkey.a, a_str.c_str(), 10);
        Hamming::sender_precomp_mask_hamming(send_set_size, masks, masks_ciphers_block, dimension, side_length, &pbkey);
        
        Hamming::fpsi_hamming_send_online(
            &socket,
            &sender_set,
            &masks, &masks_ciphers_block,
            dimension, delta, side_length,
            &pbkey
        );

        time.setTimePoint("online done");
        time.setTimePoint("fpsi done");

        std::cout << (time) << std::endl;

        auto send_bytes_present = socket.bytesSent();
        auto send_bytes_received = socket.bytesReceived();
        std::cout << "[fpsi_hamming] send sends:  " << (send_bytes_present) / 1024.0 / 1024 << "MB" << std::endl;
        std::cout << "[fpsi_hamming] send receives:  " << (send_bytes_received) / 1024.0 / 1024 << "MB" << std::endl;
    } else { // 测试模式
        Hamming::receiver_precomp_value_hamming(recv_set_size, pre_vals, dimension, delta, &pbkey);
        auto sockets = coproto::LocalAsyncSocket::makePair();
        Hamming::sender_precomp_mask_hamming(send_set_size, masks, masks_ciphers_block, dimension, side_length, &pbkey);

        std::thread thread_recv(
            Hamming::fpsi_hamming_recv_online, &sockets[0],
            &receiver_set, &unique_components,
            &pre_vals,
            dimension, delta, side_length,
            &pbkey, &prkey, result_file
        );

        std::thread thread_send(
            Hamming::fpsi_hamming_send_online, &sockets[1],
            &sender_set,
            &masks, &masks_ciphers_block,
            dimension, delta, side_length,
            &pbkey
        );

        thread_recv.join();
        thread_send.join();
        
        time.setTimePoint("online done");
        time.setTimePoint("fpsi done");

        std::cout << (time) << std::endl;

        auto recv_bytes_present = sockets[0].bytesSent();
        auto send_bytes_present = sockets[1].bytesSent();
        std::cout << "[fpsi_hamming] recv sends:  " << (recv_bytes_present) / 1024.0 / 1024 << "MB" << std::endl;
        std::cout << "[fpsi_hamming] send sends:  " << (send_bytes_present) / 1024.0 / 1024 << "MB" << std::endl;
        std::cout << "[fpsi_hamming] comm total:  " << ((recv_bytes_present) + (send_bytes_present)) / 1024.0 / 1024 << "MB" << std::endl;
    }

    mpz_clear(pbkey.a);
    mpz_clear(pbkey.N);
    mpz_clear(prkey.p);
    mpz_clear(prkey.q);

    std::cout << std::endl;

    const bool out_to_file = cmd.isSet("file");
    if (out_to_file) {
        std::string filename = "test_Hamming_m_" + std::to_string(send_set_size)
            + "_n_" + std::to_string(recv_set_size)
            + "_d_" + std::to_string(dimension)
            + "_delta_" + std::to_string(delta)
            + ".txt";
        std::ofstream mycout(filename, std::ios::app);
        mycout << std::endl << "test_Hamming ----------------------------" << std::endl;
        mycout << "role         : " << role << std::endl;
        mycout << "recv_set_size: " << recv_set_size << std::endl;
        mycout << "send_set_size: " << send_set_size << std::endl;
        mycout << "dimension:     " << dimension << std::endl;
        mycout << "delta:         " << delta << std::endl;
        mycout << "side_length:   " << side_length << std::endl;
        mycout << time << std::endl << std::endl;
        mycout.close();
    }

    return;
}

    void test_gm_fpsi_hamming1(const CLP& cmd){
        std::cout << "test_gm_fpsi_hamming ----------------------------" << std::endl;
        PRNG prng(oc::sysRandomSeed());

        const u64 dimension = cmd.getOr("hamd", 128);
        const u64 delta = cmd.getOr("hamdelta", 4);
        const u64 side_length = cmd.getOr("hamside", ((dimension / (delta + 1)) / 8) * 8);
        std::string result_file = cmd.getOr("if", std::string(""));

        // 添加命令行选项-rf和-sf
        std::string recv_file = cmd.getOr("rf", std::string(""));
        std::string send_file = cmd.getOr("sf", std::string(""));

        if (recv_file.empty() || send_file.empty()) {
            printf("Please specify recv_set file and send_set file using -rf and -sf\n");
            return;
        }

        // 从文件读取recv_set
        std::vector<BitVector> recv_set;
        std::ifstream recv_stream(recv_file);
        std::string line;
        while (std::getline(recv_stream, line)) {
            if (line.empty()) continue;
            try {
                u64 value = std::stoull(line);
                // 检查数值是否超出dimension位能表示的范围
                if (value >= (1ULL << dimension)) {
                    printf("Value %lu in recv_set exceeds %lu bits\n", value, dimension);
                    return;
                }
                // 转换为dimension位的比特向量，前面补零
                BitVector bv(dimension);
                for (u64 i = 0; i < dimension; ++i) {
                    u64 bit = (value >> (dimension - 1 - i)) & 1;
                    bv[i]= bit;
                }
                recv_set.push_back(bv);
            } catch (const std::exception& e) {
                printf("Invalid number in recv_set file: %s\n", line.c_str());
                return;
            }
        }

        // 从文件读取send_set
        std::vector<BitVector> send_set;
        std::ifstream send_stream(send_file);
        while (std::getline(send_stream, line)) {
            if (line.empty()) continue;
            try {
                u64 value = std::stoull(line);
                if (value >= (1ULL << dimension)) {
                    printf("Value %lu in send_set exceeds %lu bits\n", value, dimension);
                    return;
                }
                BitVector bv(dimension);
                for (u64 i = 0; i < dimension; ++i) {
                    u64 bit = (value >> (dimension - 1 - i)) & 1;
                    bv[i] = bit;
                }
                send_set.push_back(bv);
            } catch (const std::exception& e) {
                printf("Invalid number in send_set file: %s\n", line.c_str());
                return;
            }
        }

        const u64 recv_set_size = recv_set.size();
        const u64 send_set_size = send_set.size();

        if ((side_length == 0)) {
            printf("dimension should not be less than (threshold + 1) * 8\n");
            return;
        }
        if ((side_length > ((dimension / (delta + 1)) / 8) * 8)) {
            printf("side_length should be less than ((dimension / (threshold + 1)) / 8) * 8\n");
            return;
        }
        if ((side_length % 8 != 0)) {
            printf("side_length mod 8 should be 0\n");
            return;
        }
        if ((pow(2, side_length) <= recv_set_size)) {
            printf("pow(2, side_length) should be greater than recv_set_size\n");
            return;
        }

        std::cout << "recv_set_size: " << recv_set_size << std::endl;
        std::cout << "send_set_size: " << send_set_size << std::endl;
        std::cout << "dimension    : " << dimension << std::endl;
        std::cout << "delta        : " << delta << std::endl;
        std::cout << "side_length  : " << side_length << std::endl;

        // 计算unique_components
        std::vector<std::vector<u64>> unique_components(recv_set_size);
        for (u64 i = 0; i < recv_set_size; i++) {
            for (u64 j = 0; j < dimension; j++) {
                bool unique = true;
                for (u64 k = 0; k < recv_set_size; k++) {
                    if (k == i) continue;
                    if (recv_set[i][j] == recv_set[k][j]) {
                        unique = false;
                        break;
                    }
                }
                if (unique) {
                    unique_components[i].push_back(j);
                    // 如果已经找到delta+1个唯一分量，提前退出内层循环
                    if (unique_components[i].size() > delta + 1) {
                        break;
                    }
                }
            }
            // 检查unique_components[i]的大小是否不超过delta+1
            if (unique_components[i].size() < delta + 1) {
                printf("recv_set is not independent: no enough unique components at index %lu\n", i);
                return;
            }
        }

        pubkey_t pbkey;
        privkey_t prkey;

        mpz_init(pbkey.a);
        mpz_init(pbkey.N);
        mpz_init(prkey.p);
        mpz_init(prkey.q);
        gen_keys(&pbkey, &prkey);

        auto sockets = coproto::LocalAsyncSocket::makePair();
        Timer time;

        time.setTimePoint("Start");
        std::cout << "Start" << std::endl;

        std::stack<std::array<std::vector<element>, 2UL>> pre_vals;
        Hamming::receiver_precomp_value_hamming(recv_set_size, pre_vals, dimension, delta, &pbkey);

        std::stack<BitVector> masks;
        std::stack<std::vector<std::vector<block>>> masks_ciphers_block;
        Hamming::sender_precomp_mask_hamming(send_set_size, masks, masks_ciphers_block, dimension, side_length, &pbkey);


        time.setTimePoint("Offline done");
        std::cout << "offline done" << std::endl;

		std::thread thread_fpsi_recv(Hamming::fpsi_hamming_recv_online, &sockets[0],
        &recv_set, &unique_components,
        &pre_vals,
        dimension, delta, side_length,
        &pbkey, &prkey, result_file);

		std::thread thread_fpsi_send(Hamming::fpsi_hamming_send_online, &sockets[1],
        &send_set,
        &masks, &masks_ciphers_block,
        dimension, delta, side_length,
        &pbkey);

		thread_fpsi_recv.join();
		thread_fpsi_send.join();
        time.setTimePoint("online done");
        time.setTimePoint("fpsi done");

        std::cout << (time) << std::endl;

		auto recv_bytes_present = sockets[0].bytesSent();
		auto send_bytes_present = sockets[1].bytesSent();
        std::cout << "[fpsi_hamming] recv sends:  "<< (recv_bytes_present) / 1024.0 / 1024 << "MB" << std::endl;
		std::cout << "[fpsi_hamming] send sends:  "<< (send_bytes_present) / 1024.0 / 1024 << "MB" << std::endl;
		std::cout << "[fpsi_hamming] comm total:  "<< ((recv_bytes_present) + (send_bytes_present)) / 1024.0 / 1024 << "MB" << std::endl;

        // sockets[0].close();
        // sockets[1].close();

        std::cout << std::endl;


        mpz_clear(pbkey.a);
        mpz_clear(pbkey.N);
        mpz_clear(prkey.p);
        mpz_clear(prkey.q);

        const bool out_to_file = cmd.isSet("file");
        if(out_to_file){
            std::string filename = "test_Hamming_m_"+std::to_string(send_set_size)
                                    +"_n_"+std::to_string(recv_set_size)
                                    +"_d_"+std::to_string(dimension)
                                    +"_delta_"+std::to_string(delta)
                                    +".txt";
            std::ofstream mycout(filename, std::ios::app);
            mycout << std::endl << "test_Hamming ----------------------------" << std::endl;
            mycout << "recv_set_size: " << recv_set_size << std::endl;
            mycout << "send_set_size: " << send_set_size << std::endl;
            mycout << "dimension:     " << dimension << std::endl;
            mycout << "delta:         " << delta << std::endl;
            mycout << "side_length:   " << side_length << std::endl;
            //mycout << "intersec_size: " << intersection_size << std::endl;
		    mycout << "[Hamming] comm:" << ((recv_bytes_present) + (send_bytes_present)) / 1024.0 / 1024 << "MB" << std::endl;
            mycout << "[Hamming] time:" << (time) << std::endl;
            mycout.close();
        }

        return;

    }

// /////bp24 protocols//////////
//     void test_bp24_lp_low_dim(const CLP& cmd){
//         std::cout << "test_bp24_lp_low_dim ----------------------------" << std::endl;
//         PRNG prng(oc::sysRandomSeed());

//         const u64 dimension = cmd.getOr("d", 2);
//         const u64 delta = cmd.getOr("delta", 10);
//         const u64 side_length = delta * 2;
//         const u64 p = cmd.getOr("p", 2);
//         const u64 recv_set_size = 1ull << cmd.getOr("r", 10);
//         const u64 send_set_size = 1ull << cmd.getOr("s", 10);
//         const u64 intersection_size = cmd.getOr("i", 32);
//         if((intersection_size > recv_set_size) | (intersection_size > send_set_size)){
//             printf("intersection_size should not be greater than set_size\n");
//             return;
//         }

//         std::cout << "recv_set_size: " << recv_set_size << std::endl;
//         std::cout << "send_set_size: " << send_set_size << std::endl;
//         std::cout << "dimension    : " << dimension << std::endl;
//         std::cout << "delta        : " << delta << std::endl;
//         std::cout << "side_length  : " << side_length << std::endl;
//         std::cout << "l_p          : l_" << p << std::endl;


//         std::vector<std::vector<u64>> receiver_elements(recv_set_size, std::vector<u64>(dimension, 0));
//         std::vector<std::vector<u64>> sender_elements(send_set_size, std::vector<u64>(dimension, 0));


//         std::cout << "data init begin" << std::endl;
//         for(u64 i = 0; i < recv_set_size; i++){
//             for(u64 j = 0; j < dimension; j++){
//                 receiver_elements[i][j] = (6 * delta + 1) * (i + 1);
//             }
//         }

//         for(u64 i = 0; i < send_set_size; i++){
//             for(u64 j = 0; j < dimension; j++){
//                 sender_elements[i][j] = (prng.get<u64>()) % ((0xffff'ffff'ffff'ffff) - 3 * delta) + 1.5 * delta;
//             }
//         }

//         for(u64 i = 0; i < intersection_size; i++){
//             for(u64 j = 0; j < dimension; j++){
//                 sender_elements[i][j] = receiver_elements[i][j];
//             }
//             sender_elements[i][1] += 1;
//         }
//         std::cout << "data init done" << std::endl;

//         ///////////////////////////////////////////////////////////////////////////////////////
//         // key generate //////////////////////////////////////////////////////////////////////////////
//         Rist25519_number recv_sk(prng);
//         std::array<Rist25519_point, 2> recv_pk;
//         recv_pk[0] = Rist25519_point::mulGenerator(1);
//         recv_pk[1] = recv_sk * recv_pk[0];

// ///////////////////////////////////////
//         Timer time;
//         ///////////////////////////////////////////////////////////////////////////////////////
//         // offline //////////////////////////////////////////////////////////////////////////////
//         time.setTimePoint("Start");
//         std::vector<std::vector<FM25519_number>> fmat_vals;
//         bp24_ec::receiver_precomp_vals_ec_lp(recv_set_size, fmat_vals, dimension, delta, side_length, p, recv_sk);

//         std::vector<FM25519_point> vec_G_pow_a_H_pow_c;
//         std::vector<FM25519_number> vec_b;
//         std::vector<FM25519_point> vec_G_pow_c;
//         std::vector<std::vector<FM25519_point>> vec_G_pow_a_bj;
//         bp24_ec::sender_mask_ec_lp(send_set_size, vec_G_pow_a_H_pow_c, vec_b, vec_G_pow_c, vec_G_pow_a_bj, delta, p, recv_pk[0], recv_pk[1]);

//         std::cout << "fmat offline done" << std::endl;
//         time.setTimePoint("offline");
// // ///////////////////////////////////////
        
// 	    auto sockets = coproto::LocalAsyncSocket::makePair();

// 		std::thread thread_fmat_recv(bp24_ec::bp24_lp_low_dim_recv_online, &sockets[0],
//         &receiver_elements,
//         &fmat_vals,
//         dimension, delta, side_length, p,
//         recv_sk, recv_pk[0]);

// 		std::thread thread_fmat_send(bp24_ec::bp24_lp_low_dim_send_online, &sockets[1],
//         &sender_elements,
//         &vec_G_pow_a_H_pow_c, &vec_b, &vec_G_pow_c,
//         &vec_G_pow_a_bj,
//         dimension, delta, side_length);

// 		thread_fmat_recv.join();
// 		thread_fmat_send.join();
//         time.setTimePoint("fmat done");
//         time.setTimePoint("online done");

//         std::cout << (time) << std::endl;

// 		auto recv_bytes_present = sockets[0].bytesSent();
// 		auto send_bytes_present = sockets[1].bytesSent();
//         std::cout << "[bp24_lp] recv sends:  "<< (recv_bytes_present) / 1024.0 / 1024 << "MB" << std::endl;
// 		std::cout << "[bp24_lp] send sends:  "<< (send_bytes_present) / 1024.0 / 1024 << "MB" << std::endl;
// 		std::cout << "[bp24_lp] comm total:  "<< ((recv_bytes_present) + (send_bytes_present)) / 1024.0 / 1024 << "MB" << std::endl;

//         // sockets[0].close();
//         // sockets[1].close();

//         std::cout << std::endl;

//         const bool out_to_file = cmd.isSet("file");
//         if(out_to_file){
//             std::string filename = "test_bp24_lp_low_dim_m_"+std::to_string(send_set_size)
//                                     +"_n_"+std::to_string(recv_set_size)
//                                     +"_d_"+std::to_string(dimension)
//                                     +"_delta_"+std::to_string(delta)
//                                     +"_p_"+std::to_string(p)+".txt";
//             std::ofstream mycout(filename, std::ios::app);
//             mycout << std::endl << "test_bp24_lp_low_dim ----------------------------" << std::endl;
//             mycout << "recv_set_size: " << recv_set_size << std::endl;
//             mycout << "send_set_size: " << send_set_size << std::endl;
//             mycout << "dimension:     " << dimension << std::endl;
//             mycout << "delta:         " << delta << std::endl;
//             mycout << "side_length:   " << side_length << std::endl;
//             mycout << "l_p:           " << p << std::endl;
//             mycout << "[bp24_lp] recv sends:  "<< (recv_bytes_present) / 1024.0 / 1024 << "MB" << std::endl;
// 		    mycout << "[bp24_lp] send sends:  "<< (send_bytes_present) / 1024.0 / 1024 << "MB" << std::endl;
// 		    mycout << "[bp24_lp] comm total:  "<< ((recv_bytes_present) + (send_bytes_present)) / 1024.0 / 1024 << "MB" << std::endl;
//             mycout << time << std::endl << std::endl;
//             mycout.close();
//         }
//         return;
//     }

//     void test_bp24_linfty_low_dim(const CLP& cmd){
//         std::cout << "test_bp24_linfty_low_dim ----------------------------" << std::endl;
//         PRNG prng(oc::sysRandomSeed());

//         const u64 dimension = cmd.getOr("d", 2);
//         const u64 delta = cmd.getOr("delta", 10);
//         const u64 side_length = delta * 2;
//         const u64 p = 0;
//         const u64 recv_set_size = 1ull << cmd.getOr("r", 10);
//         const u64 send_set_size = 1ull << cmd.getOr("s", 10);
//         const u64 intersection_size = cmd.getOr("i", 32);
//         if((intersection_size > recv_set_size) | (intersection_size > send_set_size)){
//             printf("intersection_size should not be greater than set_size\n");
//             return;
//         }


//         std::cout << "recv_set_size: " << recv_set_size << std::endl;
//         std::cout << "send_set_size: " << send_set_size << std::endl;
//         std::cout << "dimension    : " << dimension << std::endl;
//         std::cout << "delta        : " << delta << std::endl;
//         std::cout << "side_length  : " << side_length << std::endl;
//         std::cout << "distance     : l_infty" << std::endl;

//         std::vector<std::vector<u64>> receiver_elements(recv_set_size, std::vector<u64>(dimension, 0));
//         std::vector<std::vector<u64>> sender_elements(send_set_size, std::vector<u64>(dimension, 0));

//         std::cout << "data init begin" << std::endl;
//         for(u64 i = 0; i < recv_set_size; i++){
//             for(u64 j = 0; j < dimension; j++){
//                 receiver_elements[i][j] = (6 * delta + 1) * (i + 1);
//             }
//         }

//         for(u64 i = 0; i < send_set_size; i++){
//             for(u64 j = 0; j < dimension; j++){
//                 sender_elements[i][j] = (prng.get<u64>()) % ((0xffff'ffff'ffff'ffff) - 3 * delta) + 1.5 * delta;
//             }
//         }

//         for(u64 i = 0; i < intersection_size; i++){
//             for(u64 j = 0; j < dimension; j++){
//                 sender_elements[i][j] = receiver_elements[i][j];
//             }
//             sender_elements[i][1] += 1;
//         }
//         std::cout << "data init done" << std::endl;

//         ///////////////////////////////////////////////////////////////////////////////////////
//         // key generate //////////////////////////////////////////////////////////////////////////////
//         Rist25519_number recv_sk(prng);
//         std::array<Rist25519_point, 2> recv_pk;
//         recv_pk[0] = Rist25519_point(prng);
//         recv_pk[1] = recv_sk * recv_pk[0];

// ///////////////////////////////////////
//         Timer time;
//         ///////////////////////////////////////////////////////////////////////////////////////
//         // offline //////////////////////////////////////////////////////////////////////////////
//         time.setTimePoint("Start");

//         std::vector<std::vector<FM25519_number>> fmat_vals;
//         bp24_ec::receiver_precomp_vals_ec_linfty(recv_set_size, fmat_vals, dimension, delta, side_length, recv_sk);

//         std::vector<FM25519_point> vec_G_pow_a;
//         std::vector<FM25519_number> vec_b;
//         std::vector<FM25519_point> vec_H_pow_a;
//         bp24_ec::sender_mask_ec_linfty(send_set_size, vec_G_pow_a, vec_b, vec_H_pow_a, recv_pk[0], recv_pk[1]);
//         std::cout << "fmat offline done" << std::endl;
//         time.setTimePoint("offline");
// // ///////////////////////////////////////
        
// 	    auto sockets = coproto::LocalAsyncSocket::makePair();

// 		std::thread thread_fmat_recv(bp24_ec::bp24_linfty_low_dim_recv_online, &sockets[0],
//         &receiver_elements,
//         &fmat_vals,
//         dimension, delta, side_length,
//         recv_sk, recv_pk[0]);

// 		std::thread thread_fmat_send(bp24_ec::bp24_linfty_low_dim_send_online, &sockets[1],
//         &sender_elements,
//         &vec_G_pow_a, &vec_b, &vec_H_pow_a,
//         dimension, delta, side_length);

// 		thread_fmat_recv.join();
// 		thread_fmat_send.join();
//         time.setTimePoint("fmat done");
//         time.setTimePoint("online done");

//         std::cout << (time) << std::endl;

// 		auto recv_bytes_present = sockets[0].bytesSent();
// 		auto send_bytes_present = sockets[1].bytesSent();
//         std::cout << "[bp24_linfty] recv sends:  "<< (recv_bytes_present) / 1024.0 / 1024 << "MB" << std::endl;
// 		std::cout << "[bp24_linfty] send sends:  "<< (send_bytes_present) / 1024.0 / 1024 << "MB" << std::endl;
// 		std::cout << "[bp24_linfty] comm total:  "<< ((recv_bytes_present) + (send_bytes_present)) / 1024.0 / 1024 << "MB" << std::endl;

//         // sockets[0].close();
//         // sockets[1].close();

//         std::cout << std::endl;

//         const bool out_to_file = cmd.isSet("file");
//         if(out_to_file){
//             std::string filename = "test_bp24_linfty_low_dim_m_"+std::to_string(send_set_size)
//                                     +"_n_"+std::to_string(recv_set_size)
//                                     +"_d_"+std::to_string(dimension)
//                                     +"_delta_"+std::to_string(delta)
//                                     +"_p_infty"+".txt";
//             std::ofstream mycout(filename, std::ios::app);
//             mycout << std::endl << "test_bp24_linfty_low_dim ----------------------------" << std::endl;
//             mycout << "recv_set_size: " << recv_set_size << std::endl;
//             mycout << "send_set_size: " << send_set_size << std::endl;
//             mycout << "dimension:     " << dimension << std::endl;
//             mycout << "delta:         " << delta << std::endl;
//             mycout << "side_length:   " << side_length << std::endl;
//             mycout << "distance:      l_infty" << std::endl;
//             mycout << "[bp24_linfty] recv sends:  "<< (recv_bytes_present) / 1024.0 / 1024 << "MB" << std::endl;
// 		    mycout << "[bp24_linfty] send sends:  "<< (send_bytes_present) / 1024.0 / 1024 << "MB" << std::endl;
// 		    mycout << "[bp24_linfty] comm total:  "<< ((recv_bytes_present) + (send_bytes_present)) / 1024.0 / 1024 << "MB" << std::endl;
//             mycout << time << std::endl << std::endl;
//             mycout.close();
//         }

//         return;
//     }

//     void test_bp24_lp_high_dim(const CLP& cmd){
//         std::cout << "test_bp24_lp_high_dim ----------------------------" << std::endl;
//         PRNG prng(oc::sysRandomSeed());

//         const u64 dimension = cmd.getOr("d", 2);
//         const u64 delta = cmd.getOr("delta", 10);
//         const u64 side_length = delta * 2;
//         const u64 p = cmd.getOr("p", 2);
//         const u64 recv_set_size = 1ull << cmd.getOr("r", 10);
//         const u64 send_set_size = 1ull << cmd.getOr("s", 10);

//         std::cout << "recv_set_size: " << recv_set_size << std::endl;
//         std::cout << "send_set_size: " << send_set_size << std::endl;
//         std::cout << "dimension    : " << dimension << std::endl;
//         std::cout << "delta        : " << delta << std::endl;
//         std::cout << "side_length  : " << side_length << std::endl;
//         std::cout << "l_p          : l_" << p << std::endl;

//         double kappa = 40;
//         double rho = 0.365;
//         if(p == 1){
//             rho = 0.5;
//         }
//         double log_e = 1.4427;
//         double N = recv_set_size;
//         u64 M = send_set_size;
//         u64 L = (u64)(((kappa) / log_e) * pow(N, rho));
//         u64 T = (u64)(((2 + ((kappa) / log_e)) * log2(N))/(log2(log2(N))));

//         double time = (N * L * (2 * delta + 1) * dimension * 40 + M * L * T * dimension) * 10 * 0.001;
//         double comm = N * L * (2 * delta + 1) * dimension * EC_CIPHER_SIZE_IN_BLOCK * 16 / 1024.0 / 1024;

//         std::cout << "rho          : " << rho << std::endl;

// 		std::cout << "[bp24_lp_high] comm lower bound:  " << comm << "MB" << std::endl;
//         std::cout << "[bp24_lp_high] time lower bound:  " << time << "ms" << std::endl << std::endl;

//         std::cout << std::endl;

//         const bool out_to_file = cmd.isSet("file");
//         if(out_to_file){
//             std::string filename = "test_bp24_lp_high_dim_m_"+std::to_string(send_set_size)
//                                     +"_n_"+std::to_string(recv_set_size)
//                                     +"_d_"+std::to_string(dimension)
//                                     +"_delta_"+std::to_string(delta)
//                                     +"_p_"+std::to_string(p)+".txt";
//             std::ofstream mycout(filename, std::ios::app);
//             mycout << std::endl << "test_bp24_lp_high_dim ----------------------------" << std::endl;
//             mycout << "recv_set_size: " << recv_set_size << std::endl;
//             mycout << "send_set_size: " << send_set_size << std::endl;
//             mycout << "dimension:     " << dimension << std::endl;
//             mycout << "delta:         " << delta << std::endl;
//             mycout << "side_length:   " << side_length << std::endl;
//             mycout << "l_p:           " << p << std::endl;
// 		    mycout << "[bp24_lp_high] comm lower bound:  " << comm << "MB" << std::endl;
//             mycout << "[bp24_lp_high] time lower bound:  " << time << "ms" << std::endl << std::endl;
//             mycout.close();
//         }

//         return;
//     }

//     void test_bp24_linfty_high_dim(const CLP& cmd){
//         std::cout << "test_bp24_linfty_high_dim ----------------------------" << std::endl;
//         PRNG prng(oc::sysRandomSeed());

//         const u64 dimension = cmd.getOr("d", 2);
//         const u64 delta = cmd.getOr("delta", 10);
//         const u64 side_length = delta * 2;
//         const u64 p = 0;
//         const u64 recv_set_size = 1ull << cmd.getOr("r", 10);
//         const u64 send_set_size = 1ull << cmd.getOr("s", 10);
//         const u64 intersection_size = cmd.getOr("i", 32);
//         if((intersection_size > recv_set_size) | (intersection_size > send_set_size)){
//             printf("intersection_size should not be greater than set_size\n");
//             return;
//         }

//         std::cout << "recv_set_size: " << recv_set_size << std::endl;
//         std::cout << "send_set_size: " << send_set_size << std::endl;
//         std::cout << "dimension    : " << dimension << std::endl;
//         std::cout << "delta        : " << delta << std::endl;
//         std::cout << "side_length  : " << side_length << std::endl;
//         std::cout << "distance     : l_infty" << std::endl;


//         std::vector<std::vector<u64>> receiver_elements(recv_set_size, std::vector<u64>(dimension, 0));
//         std::vector<u64> separate_dims(recv_set_size);

//         std::vector<std::vector<u64>> sender_elements(send_set_size, std::vector<u64>(dimension, 0));

//         printf("data init start\n");
//         for(u64 i = 0; i < recv_set_size; i++){
//             for(u64 j = 0; j < dimension; j++){
//                 receiver_elements[i][j] = (3 * delta + 1) * (i + 1);
//             }
//             separate_dims[i] = 0;
//         }

//         for(u64 i = 0; i < send_set_size; i++){
//             for(u64 j = 0; j < dimension; j++){
//                 sender_elements[i][j] = (prng.get<u64>()) % ((0xffff'ffff'ffff'ffff) - 3 * delta) + 1.5 * delta;
//             }
//         }

//         for(u64 i = 0; i < intersection_size; i++){
//             for(u64 j = 0; j < dimension; j++){
//                 sender_elements[i][j] = receiver_elements[i][j];
//             }
//             sender_elements[i][1] += 1;
//         }
//         std::cout << "data init done" << std::endl;

//         ///////////////////////////////////////////////////////////////////////////////////////
//         // key generate //////////////////////////////////////////////////////////////////////////////
//         Rist25519_number recv_sk(prng);
//         std::array<Rist25519_point, 2> recv_pk;
//         recv_pk[0] = Rist25519_point(prng);
//         recv_pk[1] = recv_sk * recv_pk[0];

// ///////////////////////////////////////
//         Timer time;
//         ///////////////////////////////////////////////////////////////////////////////////////
//         // offline //////////////////////////////////////////////////////////////////////////////
//         time.setTimePoint("Start");

//         std::stack<std::vector<FM25519_number>> vals_candidate;
//         bp24_high_dim::receiver_precomp_vals_ec_linfty(recv_set_size, vals_candidate, dimension, delta, recv_sk);

//         std::vector<FM25519_point> vec_G_pow_a;
//         std::vector<FM25519_number> vec_b;
//         std::vector<FM25519_point> vec_H_pow_a;
//         bp24_high_dim::sender_mask_ec_linfty(send_set_size, vec_G_pow_a, vec_b, vec_H_pow_a, recv_pk[0], recv_pk[1]);

//         std::cout << "fmat offline done" << std::endl;
//         time.setTimePoint("offline");
// // ///////////////////////////////////////
        
// 	    auto sockets = coproto::LocalAsyncSocket::makePair();

// 		std::thread thread_fmat_recv(bp24_high_dim::bp24_linfty_high_dim_recv_online, &sockets[0],
//         &receiver_elements, &separate_dims,
//         &vals_candidate,
//         dimension, delta,
//         recv_sk, recv_pk[0]);

// 		std::thread thread_fmat_send(bp24_high_dim::bp24_linfty_high_dim_send_online, &sockets[1],
//         &sender_elements,
//         &vec_G_pow_a, &vec_b, &vec_H_pow_a,
//         dimension, delta);

// 		thread_fmat_recv.join();
// 		thread_fmat_send.join();
//         time.setTimePoint("fmat done");
//         time.setTimePoint("online done");

//         std::cout << (time) << std::endl;

// 		auto recv_bytes_present = sockets[0].bytesSent();
// 		auto send_bytes_present = sockets[1].bytesSent();
//         std::cout << "[bp24_linfty_high] recv sends:  "<< (recv_bytes_present) / 1024.0 / 1024 << "MB" << std::endl;
// 		std::cout << "[bp24_linfty_high] send sends:  "<< (send_bytes_present) / 1024.0 / 1024 << "MB" << std::endl;
// 		std::cout << "[bp24_linfty_high] comm total:  "<< ((recv_bytes_present) + (send_bytes_present)) / 1024.0 / 1024 << "MB" << std::endl;

//         // sockets[0].close();
//         // sockets[1].close();

//         std::cout << std::endl;

//         const bool out_to_file = cmd.isSet("file");
//         if(out_to_file){
//             std::string filename = "test_bp24_linfty_high_dim_m_"+std::to_string(send_set_size)
//                                     +"_n_"+std::to_string(recv_set_size)
//                                     +"_d_"+std::to_string(dimension)
//                                     +"_delta_"+std::to_string(delta)
//                                     +"_p_infty"+".txt";
//             std::ofstream mycout(filename, std::ios::app);
//             mycout << std::endl << "test_bp24_linfty_high_dim ----------------------------" << std::endl;
//             mycout << "recv_set_size: " << recv_set_size << std::endl;
//             mycout << "send_set_size: " << send_set_size << std::endl;
//             mycout << "dimension:     " << dimension << std::endl;
//             mycout << "delta:         " << delta << std::endl;
//             mycout << "side_length:   " << side_length << std::endl;
//             mycout << "distance:      l_infty" << std::endl;
//             mycout << "[bp24_linfty_high] recv sends:  "<< (recv_bytes_present) / 1024.0 / 1024 << "MB" << std::endl;
// 		    mycout << "[bp24_linfty_high] send sends:  "<< (send_bytes_present) / 1024.0 / 1024 << "MB" << std::endl;
// 		    mycout << "[bp24_linfty_high] comm total:  "<< ((recv_bytes_present) + (send_bytes_present)) / 1024.0 / 1024 << "MB" << std::endl;
//             mycout << time << std::endl << std::endl;
//             mycout.close();
//         }

//         return;
//     }


    bool test_fpsi(const CLP& clp){
        
        bool lp_our = clp.isSet("t11");
        bool linfty_paillier_our = clp.isSet("t12");
        bool hamming_gm_our = clp.isSet("t13");

        bool lp_bp = clp.isSet("t21");
        bool linfty_bp = clp.isSet("t22");
        
        bool lp_bp_high = clp.isSet("t23");
        bool linfty_bp_high = clp.isSet("t24");

        if(lp_our){
            test_our_lp_paillier_fpsi(clp);
        }
        if(linfty_paillier_our){
            test_our_linfty_paillier_fpsi(clp);
        }
        if(hamming_gm_our){
            test_gm_fpsi_hamming(clp);
        }

        
        // if(lp_bp){
        //     test_bp24_lp_low_dim(clp);
        // }
        // if(linfty_bp){
        //     test_bp24_linfty_low_dim(clp);
        // }

        // if(lp_bp_high){
        //     test_bp24_lp_high_dim(clp);
        // }
        // if(linfty_bp_high){
        //     test_bp24_linfty_high_dim(clp);
        // }


        return 1;
    }

}