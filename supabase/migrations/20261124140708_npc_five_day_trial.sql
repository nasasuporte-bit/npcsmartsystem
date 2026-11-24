alter table public.npc_accounts
  add column trial_requested boolean not null default false,
  add column trial_expires_at timestamptz;

create function npc_private.account_has_access(account public.npc_accounts)
returns boolean
language sql
stable
set search_path to ''
as $$
  select account.status='active'
      or (account.status='pending' and account.trial_expires_at > now());
$$;
revoke all on function npc_private.account_has_access(public.npc_accounts) from public, anon, authenticated;

create function npc_private.record_trial_signup()
returns trigger
language plpgsql
security definer
set search_path to ''
as $$
begin
 if tg_op='INSERT' and new.raw_user_meta_data->>'trial'='true' then
  update public.npc_accounts
  set trial_requested=true,
      trial_expires_at=case when new.email_confirmed_at is not null then now()+interval '120 hours' end
  where id=new.id and status='pending';
 elsif tg_op='UPDATE' and new.email_confirmed_at is not null and old.email_confirmed_at is null then
  update public.npc_accounts
  set trial_expires_at=now()+interval '120 hours'
  where id=new.id and status='pending' and trial_requested and trial_expires_at is null;
 end if;
 return new;
end;
$$;

revoke all on function npc_private.record_trial_signup() from public, anon, authenticated;

-- PostgreSQL fires same-kind triggers in name order. The existing npc_auth_account
-- trigger provisions the account before npc_record_trial_signup records the trial.
create trigger npc_record_trial_signup
after insert or update of email_confirmed_at on auth.users
for each row execute function npc_private.record_trial_signup();

CREATE OR REPLACE FUNCTION npc_private.workspace_owner_id()
 RETURNS uuid
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
 select coalesce(
  (select m.owner_id from public.npc_workspace_members m
   join public.npc_accounts o on o.id=m.owner_id
   where m.user_id=auth.uid() and m.active and o.status='active' limit 1),
  (select a.id from public.npc_accounts a where a.id=auth.uid() and npc_private.account_has_access(a) limit 1)
 );
$function$;

CREATE OR REPLACE FUNCTION npc_private.guard_workspace()
 RETURNS trigger
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare
 m public.npc_workspace_members; merged jsonb; old_items jsonb; new_items jsonb; v_clients jsonb; v_sales jsonb; v_ledger jsonb;
 can_sales boolean; can_orders boolean; can_cash boolean; can_queries boolean; can_receivables boolean; can_payables boolean;
begin
 if new.owner_id<>old.owner_id or new.revision<>old.revision+1 or new.last_write_id is null or new.last_write_id is not distinct from old.last_write_id then raise exception 'Invalid workspace revision' using errcode='40001'; end if;
 if new.payload ? 'users' or new.payload ? 'workspaces' then raise exception 'Authentication data must not be stored in workspace payload'; end if;
 if old.payload ? 'createdAt' and new.payload->'createdAt' is distinct from old.payload->'createdAt' then raise exception 'Workspace creation date is immutable'; end if;
 if auth.uid()=new.owner_id then
  if not exists(select 1 from public.npc_accounts a where a.id=new.owner_id and npc_private.account_has_access(a)) then raise exception 'Workspace access inactive' using errcode='42501'; end if;
  new.updated_at=now(); return new;
 end if;
 select x.* into m from public.npc_workspace_members x join public.npc_accounts a on a.id=x.owner_id where x.user_id=auth.uid() and x.owner_id=new.owner_id and x.active and a.status='active';
 if not found then raise exception 'Workspace access denied' using errcode='42501'; end if;
 can_sales:=coalesce((m.permissions->>'sales')::boolean,false); can_orders:=coalesce((m.permissions->>'orders')::boolean,false); can_cash:=coalesce((m.permissions->>'cash')::boolean,false);
 can_queries:=coalesce((m.permissions->>'queries')::boolean,false);can_receivables:=coalesce((m.permissions->>'receivables')::boolean,false);can_payables:=coalesce((m.permissions->>'payables')::boolean,false);
 merged:=old.payload;
 if coalesce((m.permissions->>'settings')::boolean,false) then merged:=jsonb_set(merged,'{company}',new.payload->'company',true); elsif new.payload->'company' is distinct from old.payload->'company' then raise exception 'No settings write permission' using errcode='42501'; end if;
 if coalesce((m.permissions->>'products')::boolean,false) then merged:=jsonb_set(merged,'{products}',new.payload->'products',true);
 elsif can_sales or can_orders then
  old_items:=coalesce(old.payload->'products','[]'::jsonb);new_items:=coalesce(new.payload->'products','[]'::jsonb);
  if jsonb_array_length(old_items)<>jsonb_array_length(new_items) or exists(select 1 from jsonb_array_elements(old_items) o(value) left join jsonb_array_elements(new_items) n(value) on n.value->>'id'=o.value->>'id' where n.value is null or (o.value-'qty'-'version')<>(n.value-'qty'-'version')) then raise exception 'Sales/OS access may only adjust stock' using errcode='42501'; end if;
  merged:=jsonb_set(merged,'{products}',new_items,true);
 elsif new.payload->'products' is distinct from old.payload->'products' then raise exception 'No product write permission' using errcode='42501'; end if;
 if coalesce((m.permissions->>'clients')::boolean,false) then merged:=jsonb_set(merged,'{clients}',new.payload->'clients',true);
 elsif can_sales or can_orders then
  old_items:=coalesce(old.payload->'clients','[]'::jsonb);new_items:=coalesce(new.payload->'clients','[]'::jsonb);
  if exists(select 1 from jsonb_array_elements(old_items) o(value) left join jsonb_array_elements(new_items) n(value) on n.value->>'id'=o.value->>'id' where n.value is null or (o.value-'version')<>(n.value-'version')) then raise exception 'Sales/OS access cannot alter existing clients' using errcode='42501'; end if;
  select old_items||coalesce(jsonb_agg(n.value),'[]'::jsonb) into v_clients from jsonb_array_elements(new_items) n(value) where not exists(select 1 from jsonb_array_elements(old_items) o(value) where o.value->>'id'=n.value->>'id');
  merged:=jsonb_set(merged,'{clients}',v_clients,true);
 elsif new.payload->'clients' is distinct from old.payload->'clients' then raise exception 'No client write permission' using errcode='42501'; end if;
 if coalesce((m.permissions->>'suppliers')::boolean,false) then merged:=jsonb_set(merged,'{suppliers}',new.payload->'suppliers',true); elsif new.payload->'suppliers' is distinct from old.payload->'suppliers' then raise exception 'No supplier write permission' using errcode='42501'; end if;
 if can_orders then merged:=jsonb_set(merged,'{orders}',new.payload->'orders',true); elsif new.payload->'orders' is distinct from old.payload->'orders' then raise exception 'No OS write permission' using errcode='42501'; end if;
 if coalesce((m.permissions->>'cancellations')::boolean,false) then merged:=jsonb_set(merged,'{sales}',new.payload->'sales',true);
 elsif can_receivables then
  old_items:=coalesce(old.payload->'sales','[]'::jsonb);new_items:=coalesce(new.payload->'sales','[]'::jsonb);
  if exists(select 1 from jsonb_array_elements(old_items) o(value) left join jsonb_array_elements(new_items) n(value) on n.value->>'id'=o.value->>'id' where n.value is null or (n.value-'payments'-'version')<>(o.value-'payments'-'version')) then raise exception 'Receivables access cannot alter sale details' using errcode='42501'; end if;
  if exists(select 1 from jsonb_array_elements(new_items) n(value) join jsonb_array_elements(old_items) o(value) on o.value->>'id'=n.value->>'id' where jsonb_array_length(coalesce(n.value->'payments','[]'::jsonb))<jsonb_array_length(coalesce(o.value->'payments','[]'::jsonb))) then raise exception 'Receipts cannot be removed' using errcode='42501'; end if;
  merged:=jsonb_set(merged,'{sales}',new_items,true);
 elsif can_sales or can_orders then
  old_items:=coalesce(old.payload->'sales','[]'::jsonb);new_items:=coalesce(new.payload->'sales','[]'::jsonb);
  if exists(select 1 from jsonb_array_elements(new_items) n(value) join jsonb_array_elements(old_items) o(value) on o.value->>'id'=n.value->>'id' where n.value is distinct from o.value) then raise exception 'Sales history is append-only for this access' using errcode='42501'; end if;
  select old_items||coalesce(jsonb_agg(n.value),'[]'::jsonb) into v_sales from jsonb_array_elements(new_items) n(value) where not exists(select 1 from jsonb_array_elements(old_items) o(value) where o.value->>'id'=n.value->>'id');
  merged:=jsonb_set(merged,'{sales}',v_sales,true);
 elsif new.payload->'sales' is distinct from old.payload->'sales' then raise exception 'No sales write permission' using errcode='42501'; end if;
 if can_cash then merged:=jsonb_set(merged,'{ledger}',new.payload->'ledger',true);merged:=jsonb_set(merged,'{shifts}',new.payload->'shifts',true);
 elsif can_sales or can_orders or can_receivables or can_payables then
  old_items:=coalesce(old.payload->'ledger','[]'::jsonb);new_items:=coalesce(new.payload->'ledger','[]'::jsonb);
  if exists(select 1 from jsonb_array_elements(new_items) n(value) join jsonb_array_elements(old_items) o(value) on o.value->>'id'=n.value->>'id') then raise exception 'Cash history is append-only for this access' using errcode='42501'; end if;
  select old_items||coalesce(jsonb_agg(n.value),'[]'::jsonb) into v_ledger from jsonb_array_elements(new_items) n(value) where not exists(select 1 from jsonb_array_elements(old_items) o(value) where o.value->>'id'=n.value->>'id');
  merged:=jsonb_set(merged,'{ledger}',v_ledger,true);
  if coalesce(new.payload->'shifts','[]'::jsonb) is distinct from coalesce(old.payload->'shifts','[]'::jsonb) then raise exception 'Only cash permission can manage shifts' using errcode='42501'; end if;
 elsif new.payload->'ledger' is distinct from old.payload->'ledger' or new.payload->'shifts' is distinct from old.payload->'shifts' then raise exception 'No cash write permission' using errcode='42501'; end if;
 if can_payables then merged:=jsonb_set(merged,'{bills}',new.payload->'bills',true); elsif new.payload->'bills' is distinct from old.payload->'bills' then raise exception 'No payable write permission' using errcode='42501'; end if;
 if new.payload->'next' is distinct from old.payload->'next' then
  old_items:=coalesce(old.payload->'next','{}'::jsonb);new_items:=coalesce(new.payload->'next','{}'::jsonb);
  if (can_sales or can_orders) and (new_items->>'sale')::bigint >= (old_items->>'sale')::bigint then old_items:=jsonb_set(old_items,'{sale}',new_items->'sale',true); end if;
  if can_orders and (new_items->>'order')::bigint >= (old_items->>'order')::bigint then old_items:=jsonb_set(old_items,'{order}',new_items->'order',true); end if;
  if can_cash and (new_items->>'shift')::bigint >= (old_items->>'shift')::bigint then old_items:=jsonb_set(old_items,'{shift}',new_items->'shift',true); end if;
  if can_payables and (new_items->>'bill')::bigint >= (old_items->>'bill')::bigint then old_items:=jsonb_set(old_items,'{bill}',new_items->'bill',true); end if;
  merged:=jsonb_set(merged,'{next}',old_items,true);
 end if;
 new.payload:=merged;new.updated_at=now();return new;
end;$function$;

CREATE OR REPLACE FUNCTION public.npc_current_access()
 RETURNS TABLE(id uuid, email text, name text, status text, platform_admin boolean, workspace_id uuid, role text, permissions jsonb)
 LANGUAGE plpgsql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
begin
 if auth.uid() is null then return; end if;
 if exists(select 1 from public.npc_workspace_members m where m.user_id=auth.uid()) then
  return query
   select m.user_id,u.email,m.display_name,
     case when m.active and o.status='active' and u.email_confirmed_at is not null then 'active' else 'blocked' end,
     false,m.owner_id,'attendant',m.permissions
   from public.npc_workspace_members m
   join auth.users u on u.id=m.user_id
   join public.npc_accounts o on o.id=m.owner_id
   where m.user_id=auth.uid();
  return;
 end if;
 return query
  select a.id,a.email,a.name,
   case when a.status='pending' and a.trial_expires_at is not null
        then case when npc_private.account_has_access(a) then 'trial' else 'trial_expired' end
        else a.status end,
   a.platform_admin,a.id,'admin',
   jsonb_build_object('products',true,'sales',true,'clients',true,'suppliers',true,'receivables',true,'payables',true,'queries',true,'cash',true,'cancellations',true,'charts',true,'orders',true,'email',true,'labels',true,'settings',true)
   || case when a.status='pending' and npc_private.account_has_access(a)
           then jsonb_build_object('trial_expires_at',a.trial_expires_at) else '{}'::jsonb end
  from public.npc_accounts a where a.id=auth.uid();
end;
$function$;
