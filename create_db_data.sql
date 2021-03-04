INSERT INTO AUTH_CONSUMER_TBL (auth_id, dst_ip, dst_port, system_type, user_id, password, name, auth_flag, token, issued_at, expired_at, display, ssl_flag, heartbeat_state, link_loc_name) 
VALUES ( 1, 'localhost', 5000, 'NFVO', 'nfvo_sim_id', 'nfvo_sim_pw', 'nfvo_sim', 0, 'b0a5ee03b4a948cc9b6901b8e466fae3', NOW(), DATE_ADD(NOW(), interval 4000 DAY), 0, 0, 0, 'external');

