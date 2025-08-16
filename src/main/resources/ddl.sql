-- ====================================
-- 0. TRIGGER FUNCTION (Reusable)
-- ====================================
CREATE OR REPLACE FUNCTION set_updated_at()
    RETURNS TRIGGER AS
$$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ====================================
-- 1. SEQUENCES
-- ====================================
CREATE SEQUENCE roles_id_seq START 1 INCREMENT 1;
CREATE SEQUENCE users_id_seq START 1 INCREMENT 1;
CREATE SEQUENCE permissions_id_seq START 1 INCREMENT 1;
CREATE SEQUENCE roles_permissions_id_seq START 1 INCREMENT 1;

-- ====================================
-- 2. ROLES TABLE
-- ====================================
CREATE TABLE public.roles
(
    id          BIGINT PRIMARY KEY DEFAULT nextval('roles_id_seq'),
    name        VARCHAR(50) NOT NULL UNIQUE,
    description TEXT,
    created_at  TIMESTAMPTZ        DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMPTZ        DEFAULT CURRENT_TIMESTAMP
);

CREATE TRIGGER trg_roles_updated_at
    BEFORE UPDATE
    ON public.roles
    FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

-- ====================================
-- 3. USERS TABLE (One-to-Many with Roles)
-- ====================================
CREATE TABLE public.users
(
    id            BIGINT PRIMARY KEY DEFAULT nextval('users_id_seq'),
    username      VARCHAR(50)  NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    email         VARCHAR(100) UNIQUE,
    is_active     BOOLEAN            DEFAULT TRUE,
    role_id       BIGINT       NOT NULL REFERENCES public.roles (id) ON DELETE RESTRICT,
    created_at    TIMESTAMPTZ        DEFAULT CURRENT_TIMESTAMP,
    updated_at    TIMESTAMPTZ        DEFAULT CURRENT_TIMESTAMP
);

CREATE TRIGGER trg_users_updated_at
    BEFORE UPDATE
    ON public.users
    FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

-- ====================================
-- 4. PERMISSIONS TABLE
-- ====================================
CREATE TABLE public.permissions
(
    id          BIGINT PRIMARY KEY DEFAULT nextval('permissions_id_seq'),
    name        VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    created_at  TIMESTAMPTZ        DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMPTZ        DEFAULT CURRENT_TIMESTAMP
);

CREATE TRIGGER trg_permissions_updated_at
    BEFORE UPDATE
    ON public.permissions
    FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

-- ====================================
-- 5. ROLE ↔ PERMISSION (Many-to-Many with surrogate PK)
-- ====================================
CREATE TABLE public.roles_permissions
(
    id            BIGINT PRIMARY KEY DEFAULT nextval('roles_permissions_id_seq'),
    role_id       BIGINT NOT NULL REFERENCES public.roles (id) ON DELETE CASCADE,
    permission_id BIGINT NOT NULL REFERENCES public.permissions (id) ON DELETE CASCADE,
    UNIQUE (role_id, permission_id)
);

-- ====================================
-- 6. INDEXES
-- ====================================
CREATE INDEX idx_users_username ON public.users (username);
CREATE INDEX idx_roles_name ON public.roles (name);
CREATE INDEX idx_permissions_name ON public.permissions (name);

-- ====================================
-- 7. SAMPLE DATA
-- ====================================
INSERT INTO public.roles (name, description)
VALUES ('admin', 'Full system access'),
       ('manager', 'Manage users and view reports'),
       ('user', 'Basic access');

INSERT INTO public.permissions (name, description)
VALUES ('read_users', 'View list of users'),
       ('create_users', 'Add new users'),
       ('update_users', 'Edit user details'),
       ('delete_users', 'Remove users'),
       ('view_reports', 'View system reports');

-- Admin gets everything
INSERT INTO public.roles_permissions (role_id, permission_id)
SELECT 1, id
FROM public.permissions;

-- Manager gets limited permissions
INSERT INTO public.roles_permissions (role_id, permission_id)
VALUES (2, 1), -- read_users
       (2, 3), -- update_users
       (2, 5);
-- view_reports

-- Basic user gets only read_users
INSERT INTO public.roles_permissions (role_id, permission_id)
VALUES (3, 1);

-- Create sample users with single role each
INSERT INTO public.users (username, password_hash, email, role_id)
VALUES ('superadmin', 'hash_superadmin', 'admin@example.com', 1), -- admin
       ('john', 'hash_john', 'john@example.com', 2),              -- manager
       ('jane', 'hash_jane', 'jane@example.com', 3); -- user

-- ====================================
-- 8. VIEW
-- ====================================
CREATE OR REPLACE VIEW vw_roles_with_permissions AS
SELECT gen_random_uuid() AS id,
       r.id              AS role_id,
       r.name            AS role_name,
       r.description     AS role_description,
       p.id              AS permission_id,
       p.name            AS permission_name,
       p.description     AS permission_description
FROM roles r
         JOIN roles_permissions rp ON r.id = rp.role_id
         JOIN permissions p ON p.id = rp.permission_id;