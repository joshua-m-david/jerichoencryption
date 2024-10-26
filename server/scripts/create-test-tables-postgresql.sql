--
-- PostgreSQL database dump
--

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'SQL_ASCII';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: jerichotestdb; Type: DATABASE; Schema: -; Owner: jerichouser
--

CREATE DATABASE jerichotestdb WITH TEMPLATE = template0 ENCODING = 'UTF8' LC_COLLATE = 'en_US.UTF-8' LC_CTYPE = 'en_US.UTF-8';


ALTER DATABASE jerichotestdb OWNER TO jerichouser;

\connect jerichotestdb

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'SQL_ASCII';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_with_oids = false;

--
-- Name: messages; Type: TABLE; Schema: public; Owner: jerichouser
--

CREATE TABLE public.messages (
    message_id bigint NOT NULL,
    from_user character varying(10),
    message character varying(384),
    read_by_alpha boolean,
    read_by_bravo boolean,
    read_by_charlie boolean,
    read_by_delta boolean,
    read_by_echo boolean,
    read_by_foxtrot boolean,
    read_by_golf boolean
);


ALTER TABLE public.messages OWNER TO jerichouser;

--
-- Name: messages_message_id_seq; Type: SEQUENCE; Schema: public; Owner: jerichouser
--

CREATE SEQUENCE public.messages_message_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.messages_message_id_seq OWNER TO jerichouser;

--
-- Name: messages_message_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: jerichouser
--

ALTER SEQUENCE public.messages_message_id_seq OWNED BY public.messages.message_id;


--
-- Name: nonces; Type: TABLE; Schema: public; Owner: jerichouser
--

CREATE TABLE public.nonces (
    nonce_id bigint NOT NULL,
    nonce_sent_timestamp bigint,
    nonce character varying(128)
);


ALTER TABLE public.nonces OWNER TO jerichouser;

--
-- Name: nonces_nonce_id_seq; Type: SEQUENCE; Schema: public; Owner: jerichouser
--

CREATE SEQUENCE public.nonces_nonce_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.nonces_nonce_id_seq OWNER TO jerichouser;

--
-- Name: nonces_nonce_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: jerichouser
--

ALTER SEQUENCE public.nonces_nonce_id_seq OWNED BY public.nonces.nonce_id;


--
-- Name: settings; Type: TABLE; Schema: public; Owner: jerichouser
--

CREATE TABLE public.settings (
    settings_id smallint NOT NULL,
    test_connection boolean,
    cleanup_last_run bigint
);


ALTER TABLE public.settings OWNER TO jerichouser;

--
-- Name: settings_settings_id_seq; Type: SEQUENCE; Schema: public; Owner: jerichouser
--

CREATE SEQUENCE public.settings_settings_id_seq
    AS smallint
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.settings_settings_id_seq OWNER TO jerichouser;

--
-- Name: settings_settings_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: jerichouser
--

ALTER SEQUENCE public.settings_settings_id_seq OWNED BY public.settings.settings_id;


--
-- Name: messages message_id; Type: DEFAULT; Schema: public; Owner: jerichouser
--

ALTER TABLE ONLY public.messages ALTER COLUMN message_id SET DEFAULT nextval('public.messages_message_id_seq'::regclass);


--
-- Name: nonces nonce_id; Type: DEFAULT; Schema: public; Owner: jerichouser
--

ALTER TABLE ONLY public.nonces ALTER COLUMN nonce_id SET DEFAULT nextval('public.nonces_nonce_id_seq'::regclass);


--
-- Name: settings settings_id; Type: DEFAULT; Schema: public; Owner: jerichouser
--

ALTER TABLE ONLY public.settings ALTER COLUMN settings_id SET DEFAULT nextval('public.settings_settings_id_seq'::regclass);


--
-- Data for Name: messages; Type: TABLE DATA; Schema: public; Owner: jerichouser
--



--
-- Data for Name: nonces; Type: TABLE DATA; Schema: public; Owner: jerichouser
--



--
-- Data for Name: settings; Type: TABLE DATA; Schema: public; Owner: jerichouser
--

INSERT INTO public.settings (settings_id, test_connection, cleanup_last_run) VALUES (1, true, 1399156649);


--
-- Name: messages_message_id_seq; Type: SEQUENCE SET; Schema: public; Owner: jerichouser
--

SELECT pg_catalog.setval('public.messages_message_id_seq', 1, false);


--
-- Name: nonces_nonce_id_seq; Type: SEQUENCE SET; Schema: public; Owner: jerichouser
--

SELECT pg_catalog.setval('public.nonces_nonce_id_seq', 1, false);


--
-- Name: settings_settings_id_seq; Type: SEQUENCE SET; Schema: public; Owner: jerichouser
--

SELECT pg_catalog.setval('public.settings_settings_id_seq', 1, true);


--
-- Name: messages messages_pkey; Type: CONSTRAINT; Schema: public; Owner: jerichouser
--

ALTER TABLE ONLY public.messages
    ADD CONSTRAINT messages_pkey PRIMARY KEY (message_id);


--
-- Name: nonces nonces_pkey; Type: CONSTRAINT; Schema: public; Owner: jerichouser
--

ALTER TABLE ONLY public.nonces
    ADD CONSTRAINT nonces_pkey PRIMARY KEY (nonce_id);


--
-- Name: settings settings_pkey; Type: CONSTRAINT; Schema: public; Owner: jerichouser
--

ALTER TABLE ONLY public.settings
    ADD CONSTRAINT settings_pkey PRIMARY KEY (settings_id);


--
-- PostgreSQL database dump complete
--

