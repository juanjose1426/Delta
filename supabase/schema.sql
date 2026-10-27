-- Dubai Parfums / Supabase PostgreSQL
-- Ejecuta este archivo en Supabase > SQL Editor. No incluyas service_role en el navegador.
create extension if not exists pgcrypto;
create type public.app_role as enum ('customer','admin');
create table if not exists public.profiles (
 id uuid primary key references auth.users(id) on delete cascade,
 full_name text,
 email text,
 role public.app_role not null default 'customer',
 created_at timestamptz not null default now()
);
create table if not exists public.products (
 id uuid primary key default gen_random_uuid(),
 name text not null,
 brand text,
 image_url text,
 description text,
 family text,
 weather_tags text[] not null default '{}',
 active boolean not null default true,
 created_at timestamptz not null default now(),
 updated_at timestamptz not null default now()
);
create table if not exists public.product_variants (
 id uuid primary key default gen_random_uuid(),
 product_id uuid not null references public.products(id) on delete restrict,
 sku text not null unique,
 size_ml integer check (size_ml is null or size_ml > 0),
 retail_price numeric(12,2) not null check (retail_price >= 0),
 wholesale_price numeric(12,2) not null check (wholesale_price >= 0),
 wholesale_min_qty integer not null default 6 check (wholesale_min_qty > 0),
 stock integer not null default 0 check (stock >= 0),
 stock_min integer not null default 3 check (stock_min >= 0),
 active boolean not null default true,
 created_at timestamptz not null default now()
);
create table if not exists public.inventory_movements (
 id uuid primary key default gen_random_uuid(),
 variant_id uuid not null references public.product_variants(id) on delete restrict,
 movement_type text not null check (movement_type in ('entry','sale','adjustment','return')),
 quantity_delta integer not null,
 notes text,
 created_by uuid references auth.users(id) on delete set null,
 created_at timestamptz not null default now()
);
create table if not exists public.orders (
 id uuid primary key default gen_random_uuid(),
 user_id uuid not null references auth.users(id) on delete restrict,
 total numeric(12,2) not null check (total >= 0),
 status text not null default 'pending' check (status in ('pending','confirmed','paid','shipped','completed','cancelled')),
 channel text not null default 'web',
 created_at timestamptz not null default now()
);
create table if not exists public.order_items (
 id uuid primary key default gen_random_uuid(),
 order_id uuid not null references public.orders(id) on delete cascade,
 variant_id uuid not null references public.product_variants(id) on delete restrict,
 product_name_snapshot text not null,
 variant_snapshot text,
 unit_price numeric(12,2) not null check (unit_price >= 0),
 quantity integer not null check (quantity > 0),
 subtotal numeric(12,2) not null check (subtotal >= 0)
);
create table if not exists public.quiz_results (
 id uuid primary key default gen_random_uuid(),
 user_id uuid references auth.users(id) on delete set null,
 city text,
 weather text,
 preferred_family text,
 occasion text,
 budget_cop numeric(12,2),
 recommended_product_ids uuid[] not null default '{}',
 created_at timestamptz not null default now()
);
create index if not exists product_variants_product_id_idx on public.product_variants(product_id);
create index if not exists orders_user_id_idx on public.orders(user_id);
create index if not exists orders_created_at_idx on public.orders(created_at desc);
create index if not exists inventory_movements_variant_idx on public.inventory_movements(variant_id,created_at desc);

create or replace function public.is_admin()
returns boolean language sql stable security definer set search_path = public
as $$ select exists(select 1 from public.profiles p where p.id = auth.uid() and p.role = 'admin'); $$;
revoke all on function public.is_admin() from public;
grant execute on function public.is_admin() to authenticated;

create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public
as $$ begin
 insert into public.profiles(id,full_name,email) values(new.id, coalesce(new.raw_user_meta_data->>'full_name',''), new.email)
 on conflict (id) do update set email=excluded.email;
 return new;
end; $$;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users for each row execute procedure public.handle_new_user();

alter table public.profiles enable row level security;
alter table public.products enable row level security;
alter table public.product_variants enable row level security;
alter table public.inventory_movements enable row level security;
alter table public.orders enable row level security;
alter table public.order_items enable row level security;
alter table public.quiz_results enable row level security;

-- Public can read only published products and active variants; stock is exposed for storefront availability.
drop policy if exists "Public reads active products" on public.products;
create policy "Public reads active products" on public.products for select using (active = true or public.is_admin());
drop policy if exists "Admins manage products" on public.products;
create policy "Admins manage products" on public.products for all to authenticated using (public.is_admin()) with check (public.is_admin());
drop policy if exists "Public reads active variants" on public.product_variants;
create policy "Public reads active variants" on public.product_variants for select using ((active = true and exists(select 1 from public.products p where p.id=product_id and p.active=true)) or public.is_admin());
drop policy if exists "Admins manage variants" on public.product_variants;
create policy "Admins manage variants" on public.product_variants for all to authenticated using (public.is_admin()) with check (public.is_admin());
drop policy if exists "Users read own profile" on public.profiles;
create policy "Users read own profile" on public.profiles for select to authenticated using (id=auth.uid() or public.is_admin());
-- Los clientes no pueden actualizar directamente role/email desde el navegador.
drop policy if exists "Admins manage profiles" on public.profiles;
create policy "Admins manage profiles" on public.profiles for all to authenticated using (public.is_admin()) with check (public.is_admin());
drop policy if exists "Users create own orders" on public.orders;
create policy "Users create own orders" on public.orders for insert to authenticated with check (user_id=auth.uid());
drop policy if exists "Users read own orders" on public.orders;
create policy "Users read own orders" on public.orders for select to authenticated using (user_id=auth.uid() or public.is_admin());
drop policy if exists "Admins update orders" on public.orders;
create policy "Admins update orders" on public.orders for update to authenticated using (public.is_admin()) with check (public.is_admin());
drop policy if exists "Users create own order items" on public.order_items;
create policy "Users create own order items" on public.order_items for insert to authenticated with check (exists(select 1 from public.orders o where o.id=order_id and o.user_id=auth.uid()));
drop policy if exists "Users read own order items" on public.order_items;
create policy "Users read own order items" on public.order_items for select to authenticated using (exists(select 1 from public.orders o where o.id=order_id and (o.user_id=auth.uid() or public.is_admin())));
drop policy if exists "Admins manage order items" on public.order_items;
create policy "Admins manage order items" on public.order_items for all to authenticated using (public.is_admin()) with check (public.is_admin());
drop policy if exists "Users create own quiz results" on public.quiz_results;
create policy "Users create own quiz results" on public.quiz_results for insert to authenticated with check (user_id is null or user_id=auth.uid());
drop policy if exists "Users read own quiz results" on public.quiz_results;
create policy "Users read own quiz results" on public.quiz_results for select to authenticated using (user_id=auth.uid() or public.is_admin());
drop policy if exists "Admins read inventory movements" on public.inventory_movements;
create policy "Admins read inventory movements" on public.inventory_movements for select to authenticated using (public.is_admin());
drop policy if exists "Admins insert inventory movements" on public.inventory_movements;
create policy "Admins insert inventory movements" on public.inventory_movements for insert to authenticated with check (public.is_admin());
drop policy if exists "Admins update inventory movements" on public.inventory_movements;
create policy "Admins update inventory movements" on public.inventory_movements for update to authenticated using (public.is_admin()) with check (public.is_admin());

-- IMPORTANT: create your first account via the website, then set its role manually in SQL Editor:
-- update public.profiles set role = 'admin' where email = 'TU_CORREO_ADMIN';
-- Never permit public self-registration to assign the admin role.
