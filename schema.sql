DROP TABLE IF EXISTS trials;

CREATE TABLE trials
(
    id uuid PRIMARY KEY,
    name character varying(120) NOT NULL,
    email character varying(120) NOT NULL,
    status character varying (32) NOT NULL,
    ssh_public_key character varying(4000),
    ssh_private_key character varying(1000),
    application_id character varying(30),
    created_at timestamp with time zone,
    expires_at timestamp with time zone
);
