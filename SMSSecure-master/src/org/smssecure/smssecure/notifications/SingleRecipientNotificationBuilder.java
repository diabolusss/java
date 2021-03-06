package org.smssecure.smssecure.notifications;

import android.app.Notification;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.graphics.Bitmap;
import android.graphics.drawable.Drawable;
import android.net.Uri;
import android.os.Build;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.v4.app.NotificationCompat;
import android.support.v4.app.NotificationCompat.Action;
import android.support.v4.app.RemoteInput;
import android.text.SpannableStringBuilder;
import android.util.Log;

import com.bumptech.glide.Glide;

import org.smssecure.smssecure.R;
import org.smssecure.smssecure.crypto.MasterSecret;
import org.smssecure.smssecure.mms.DecryptableStreamUriLoader;
import org.smssecure.smssecure.mms.Slide;
import org.smssecure.smssecure.mms.SlideDeck;
import org.smssecure.smssecure.preferences.NotificationPrivacyPreference;
import org.smssecure.smssecure.recipients.Recipient;
import org.smssecure.smssecure.util.BitmapUtil;
import org.smssecure.smssecure.util.ListenableFutureTask;

import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.ExecutionException;

public class SingleRecipientNotificationBuilder extends AbstractNotificationBuilder {

  private static final String TAG = SingleRecipientNotificationBuilder.class.getSimpleName();

  private final List<CharSequence> messageBodies = new LinkedList<>();

  private       ListenableFutureTask<SlideDeck> slideDeck;
  private final MasterSecret                    masterSecret;

  public SingleRecipientNotificationBuilder(@NonNull Context context,
                                            @Nullable MasterSecret masterSecret,
                                            @NonNull NotificationPrivacyPreference privacy)
  {
    super(context, privacy);
    this.masterSecret = masterSecret;

    setSmallIcon(R.drawable.icon_notification);
    setColor(context.getResources().getColor(R.color.smssecure_primary));
    setPriority(NotificationCompat.PRIORITY_HIGH);
    setCategory(NotificationCompat.CATEGORY_MESSAGE);
    setDeleteIntent(PendingIntent.getBroadcast(context, 0, new Intent(MessageNotifier.DeleteReceiver.DELETE_REMINDER_ACTION), 0));
  }

  public void setSender(@NonNull Recipient recipient) {
    if (privacy.isDisplayContact()) {
      setContentTitle(recipient.toShortString());

      if (recipient.getContactUri() != null) {
        addPerson(recipient.getContactUri().toString());
      }

      setLargeIcon(recipient.getContactPhoto()
                            .asDrawable(context, recipient.getColor()
                                                          .toConversationColor(context)));
    } else {
      setContentTitle(context.getString(R.string.SingleRecipientNotificationBuilder_new_smssecure_message));
      setLargeIcon(Recipient.getUnknownRecipient()
                            .getContactPhoto()
                            .asDrawable(context, Recipient.getUnknownRecipient()
                                                          .getColor()
                                                          .toConversationColor(context)));
    }
  }

  public void setMessageCount(int messageCount) {
    setContentInfo(String.valueOf(messageCount));
    setNumber(messageCount);
  }

  public void setPrimaryMessageBody(CharSequence message, @Nullable ListenableFutureTask<SlideDeck> slideDeck) {
    if (privacy.isDisplayMessage()) {
      setContentText(message);
      this.slideDeck = slideDeck;
    } else {
      setContentText(context.getString(R.string.SingleRecipientNotificationBuilder_contents_hidden));
    }
  }

  public void addActions(@Nullable MasterSecret masterSecret,
                         @NonNull PendingIntent markReadIntent,
                         @NonNull PendingIntent quickReplyIntent,
                         @NonNull PendingIntent wearableReplyIntent)
  {
    Action markAsReadAction = new Action(R.drawable.check,
                                         context.getString(R.string.MessageNotifier_mark_read),
                                         markReadIntent);

    if (masterSecret != null) {
      Action replyAction = new Action(R.drawable.ic_reply_white_36dp,
                                      context.getString(R.string.MessageNotifier_reply),
                                      quickReplyIntent);

      Action wearableReplyAction = new Action.Builder(R.drawable.ic_reply,
                                                      context.getString(R.string.MessageNotifier_reply),
                                                      wearableReplyIntent)
          .addRemoteInput(new RemoteInput.Builder(MessageNotifier.EXTRA_VOICE_REPLY)
                              .setLabel(context.getString(R.string.MessageNotifier_reply)).build())
          .build();

      addAction(markAsReadAction);
      addAction(replyAction);

      extend(new NotificationCompat.WearableExtender().addAction(markAsReadAction)
                                                      .addAction(wearableReplyAction));
    } else {
      addAction(markAsReadAction);

      extend(new NotificationCompat.WearableExtender().addAction(markAsReadAction));
    }
  }

  public void addMessageBody(@Nullable CharSequence messageBody) {
    if (privacy.isDisplayMessage()) {
      messageBodies.add(messageBody == null ? "" : messageBody);
    }
  }

  public void setTicker(@NonNull Recipient recipient, @Nullable CharSequence message) {
    if (privacy.isDisplayMessage()) {
      setTicker(getStyledMessage(recipient, message));
    } else if (privacy.isDisplayContact()) {
      setTicker(getStyledMessage(recipient, context.getString(R.string.SingleRecipientNotificationBuilder_new_smssecure_message)));
    } else {
      setTicker(context.getString(R.string.SingleRecipientNotificationBuilder_new_smssecure_message));
    }
  }

  @Override
  public Notification build() {
    if (privacy.isDisplayMessage()) {
      if (messageBodies.size() == 1 && hasBigPictureSlide(slideDeck)) {
        assert masterSecret != null;
        setStyle(new NotificationCompat.BigPictureStyle()
                     .bigPicture(getBigPicture(masterSecret, slideDeck))
                     .setSummaryText(getBigText(messageBodies)));
      } else {
        setStyle(new NotificationCompat.BigTextStyle().bigText(getBigText(messageBodies)));
      }
    }

    return super.build();
  }

  private void setLargeIcon(@Nullable Drawable drawable) {
    if (drawable != null) {
      int    largeIconTargetSize  = context.getResources().getDimensionPixelSize(R.dimen.contact_photo_target_size);
      Bitmap recipientPhotoBitmap = BitmapUtil.createFromDrawable(drawable, largeIconTargetSize, largeIconTargetSize);

      if (recipientPhotoBitmap != null) {
        setLargeIcon(recipientPhotoBitmap);
      }
    }
  }

  private boolean hasBigPictureSlide(@Nullable ListenableFutureTask<SlideDeck> slideDeck) {
    try {
      if (masterSecret == null || slideDeck == null || Build.VERSION.SDK_INT < 16) {
        return false;
      }

      Slide thumbnailSlide = slideDeck.get().getThumbnailSlide();

      if (thumbnailSlide == null) return false;

      Uri uri = thumbnailSlide.getThumbnailUri();

      if (uri == null) return false;

      DecryptableStreamUriLoader.DecryptableUri decryptableUri = new DecryptableStreamUriLoader.DecryptableUri(masterSecret, uri);

      return decryptableUri != null    &&
             thumbnailSlide.hasImage() &&
             !thumbnailSlide.isInProgress();

    } catch (InterruptedException | ExecutionException e) {
      Log.w(TAG, e);
      return false;
    }
  }

  private Bitmap getBigPicture(@NonNull MasterSecret masterSecret,
                               @NonNull ListenableFutureTask<SlideDeck> slideDeck)
  {
    try {
      Uri uri = slideDeck.get().getThumbnailSlide().getThumbnailUri();

      return Glide.with(context)
                  .load(new DecryptableStreamUriLoader.DecryptableUri(masterSecret, uri))
                  .asBitmap()
                  .into(500, 500)
                  .get();
    } catch (InterruptedException | ExecutionException e) {
      throw new AssertionError(e);
    }
  }

  private CharSequence getBigText(List<CharSequence> messageBodies) {
    SpannableStringBuilder content = new SpannableStringBuilder();

    for (CharSequence message : messageBodies) {
      content.append(message);
      content.append('\n');
    }

    return content;
  }

}
