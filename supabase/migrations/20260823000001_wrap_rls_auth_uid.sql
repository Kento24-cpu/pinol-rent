-- Best-practices hardening (P3): wrap auth.uid() in (select auth.uid()) inside RLS
-- policies. Per Supabase guidance this evaluates the function once and caches it
-- instead of calling it per row, avoiding per-row auth.uid() overhead on large
-- tables. Behavior is unchanged; only the policy expressions are rewritten.
-- All policies are dropped and recreated with idempotent `drop policy if exists`.

-- Profiles
drop policy if exists "profiles_read_all" on profiles;
create policy "profiles_read_all" on profiles
  for select using ((select auth.uid()) is not null);

drop policy if exists "profiles_insert_own" on profiles;
create policy "profiles_insert_own" on profiles
  for insert with check ((select auth.uid()) = id);

drop policy if exists "profiles_update_own" on profiles;
create policy "profiles_update_own" on profiles
  for update using ((select auth.uid()) = id);

-- Cars
drop policy if exists "cars_read_all" on cars;
create policy "cars_read_all" on cars
  for select using (available = true or (select auth.uid()) = owner_id);

drop policy if exists "cars_insert_own" on cars;
create policy "cars_insert_own" on cars
  for insert with check ((select auth.uid()) = owner_id);

drop policy if exists "cars_update_own" on cars;
create policy "cars_update_own" on cars
  for update using ((select auth.uid()) = owner_id);

drop policy if exists "cars_delete_own" on cars;
create policy "cars_delete_own" on cars
  for delete using ((select auth.uid()) = owner_id);

-- Bookings
drop policy if exists "bookings_select" on bookings;
create policy "bookings_select" on bookings
  for select using (
    (select auth.uid()) = renter_id
    or exists (
      select 1 from cars where cars.id = bookings.car_id and cars.owner_id = (select auth.uid())
    )
  );

drop policy if exists "bookings_insert" on bookings;
create policy "bookings_insert" on bookings
  for insert with check ((select auth.uid()) = renter_id);

drop policy if exists "bookings_update" on bookings;
create policy "bookings_update" on bookings
  for update using (
    (select auth.uid()) = renter_id
    or exists (
      select 1 from cars where cars.id = bookings.car_id and cars.owner_id = (select auth.uid())
    )
  );

drop policy if exists "bookings_delete" on bookings;
create policy "bookings_delete" on bookings
  for delete using (
    (select auth.uid()) = renter_id
    or exists (
      select 1 from cars where cars.id = bookings.car_id and cars.owner_id = (select auth.uid())
    )
  );

-- Reviews
drop policy if exists "reviews_select_participant" on reviews;
create policy "reviews_select_participant" on reviews
  for select using (
    (select auth.uid()) = renter_id
    or exists (
      select 1 from cars where cars.id = reviews.car_id and cars.owner_id = (select auth.uid())
    )
  );

drop policy if exists "reviews_insert_own" on reviews;
create policy "reviews_insert_own" on reviews
  for insert with check (
    (select auth.uid()) = renter_id
    and exists (
      select 1 from bookings
      where bookings.id = reviews.booking_id
        and bookings.renter_id = (select auth.uid())
        and bookings.status = 'completed'
    )
  );

drop policy if exists "reviews_update_own" on reviews;
create policy "reviews_update_own" on reviews
  for update using ((select auth.uid()) = renter_id)
  with check ((select auth.uid()) = renter_id);

drop policy if exists "reviews_delete_own" on reviews;
create policy "reviews_delete_own" on reviews
  for delete using (
    (select auth.uid()) = renter_id
    and exists (
      select 1 from bookings
      where bookings.id = reviews.booking_id
        and bookings.status = 'completed'
    )
  );

-- Notification prefs
drop policy if exists "notification_prefs_select_own" on notification_prefs;
create policy "notification_prefs_select_own" on notification_prefs
  for select using ((select auth.uid()) = user_id);

drop policy if exists "notification_prefs_insert_own" on notification_prefs;
create policy "notification_prefs_insert_own" on notification_prefs
  for insert with check ((select auth.uid()) = user_id);

drop policy if exists "notification_prefs_update_own" on notification_prefs;
create policy "notification_prefs_update_own" on notification_prefs
  for update using ((select auth.uid()) = user_id)
  with check ((select auth.uid()) = user_id);

-- Conversations
drop policy if exists "conversations_select_participant" on conversations;
create policy "conversations_select_participant" on conversations
  for select using ((select auth.uid()) = renter_id or (select auth.uid()) = owner_id);

drop policy if exists "conversations_insert_participant" on conversations;
create policy "conversations_insert_participant" on conversations
  for insert with check ((select auth.uid()) = renter_id or (select auth.uid()) = owner_id);

drop policy if exists "conversations_update_last_message" on conversations;
create policy "conversations_update_last_message" on conversations
  for update using ((select auth.uid()) = renter_id or (select auth.uid()) = owner_id);

-- Messages
drop policy if exists "messages_select_participant" on messages;
create policy "messages_select_participant" on messages
  for select using (
    exists (
      select 1 from conversations
      where conversations.id = messages.conversation_id
        and ((select auth.uid()) = conversations.renter_id or (select auth.uid()) = conversations.owner_id)
    )
  );

drop policy if exists "messages_insert_participant" on messages;
create policy "messages_insert_participant" on messages
  for insert with check (
    exists (
      select 1 from conversations
      where conversations.id = conversation_id
        and ((select auth.uid()) = conversations.renter_id or (select auth.uid()) = conversations.owner_id)
    )
  );

drop policy if exists "messages_update_own" on messages;
create policy "messages_update_own" on messages
  for update using (sender_id = (select auth.uid()))
  with check (sender_id = (select auth.uid()));

-- Storage: car-images
drop policy if exists "car_images_insert_own" on storage.objects;
create policy "car_images_insert_own" on storage.objects
  for insert with check (
    bucket_id = 'car-images'
    and auth.role() = 'authenticated'
    and (storage.foldername(name))[1] = (select auth.uid())::text
  );

drop policy if exists "car_images_update_own" on storage.objects;
create policy "car_images_update_own" on storage.objects
  for update using (
    bucket_id = 'car-images'
    and auth.role() = 'authenticated'
    and (storage.foldername(name))[1] = (select auth.uid())::text
  );

drop policy if exists "car_images_delete_own" on storage.objects;
create policy "car_images_delete_own" on storage.objects
  for delete using (
    bucket_id = 'car-images'
    and auth.role() = 'authenticated'
    and (storage.foldername(name))[1] = (select auth.uid())::text
  );

-- Storage: avatars
drop policy if exists "avatars_insert_own" on storage.objects;
create policy "avatars_insert_own" on storage.objects
  for insert with check (
    bucket_id = 'avatars'
    and auth.role() = 'authenticated'
    and (storage.foldername(name))[1] = (select auth.uid())::text
  );

drop policy if exists "avatars_update_own" on storage.objects;
create policy "avatars_update_own" on storage.objects
  for update using (
    bucket_id = 'avatars'
    and auth.role() = 'authenticated'
    and (storage.foldername(name))[1] = (select auth.uid())::text
  );

drop policy if exists "avatars_delete_own" on storage.objects;
create policy "avatars_delete_own" on storage.objects
  for delete using (
    bucket_id = 'avatars'
    and auth.role() = 'authenticated'
    and (storage.foldername(name))[1] = (select auth.uid())::text
  );

-- Storage: chat-attachments
drop policy if exists "chat_attachments_insert_own" on storage.objects;
create policy "chat_attachments_insert_own" on storage.objects
  for insert with check (
    bucket_id = 'chat-attachments'
    and auth.role() = 'authenticated'
    and (storage.foldername(name))[1] = (select auth.uid())::text
  );

drop policy if exists "chat_attachments_update_own" on storage.objects;
create policy "chat_attachments_update_own" on storage.objects
  for update using (
    bucket_id = 'chat-attachments'
    and auth.role() = 'authenticated'
    and (storage.foldername(name))[1] = (select auth.uid())::text
  );

drop policy if exists "chat_attachments_delete_own" on storage.objects;
create policy "chat_attachments_delete_own" on storage.objects
  for delete using (
    bucket_id = 'chat-attachments'
    and auth.role() = 'authenticated'
    and (storage.foldername(name))[1] = (select auth.uid())::text
  );
