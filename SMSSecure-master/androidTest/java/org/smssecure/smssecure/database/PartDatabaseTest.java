package org.smssecure.smssecure.database;

import android.net.Uri;

import org.smssecure.smssecure.SMSSecureTestCase;
import org.smssecure.smssecure.crypto.MasterSecret;
import org.smssecure.smssecure.database.PartDatabase.PartId;

import java.io.FileNotFoundException;
import java.io.InputStream;
import java.util.concurrent.ExecutionException;

import ws.com.google.android.mms.pdu.PduPart;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyFloat;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class PartDatabaseTest extends SMSSecureTestCase {
  private static final PartId PART_ID = new PartId(1L, 1L);

  private PartDatabase database;

  @Override
  public void setUp() {
    database = spy(DatabaseFactory.getPartDatabase(getInstrumentation().getTargetContext()));
  }

  public void testTaskNotRunWhenThumbnailExists() throws Exception {
    when(database.getPart(PART_ID)).thenReturn(getPduPartSkeleton("x/x"));
    doReturn(mock(InputStream.class)).when(database).getDataStream(any(MasterSecret.class), any(PartId.class), eq("thumbnail"));

    database.getThumbnailStream(null, PART_ID);

    verify(database, never()).updatePartThumbnail(any(MasterSecret.class), any(PartId.class), any(PduPart.class), any(InputStream.class), anyFloat());
  }

  public void testTaskRunWhenThumbnailMissing() throws Exception {
    when(database.getPart(PART_ID)).thenReturn(getPduPartSkeleton("image/png"));
    doReturn(null).when(database).getDataStream(any(MasterSecret.class), any(PartId.class), eq("thumbnail"));
    doNothing().when(database).updatePartThumbnail(any(MasterSecret.class), any(PartId.class), any(PduPart.class), any(InputStream.class), anyFloat());

    try {
      database.new ThumbnailFetchCallable(mock(MasterSecret.class), PART_ID).call();
      throw new AssertionError("didn't try to generate thumbnail");
    } catch (ExecutionException e){
      if (!(e.getCause() instanceof FileNotFoundException)) {
        throw new AssertionError("wrong error type");
      }
      // success
    }
  }

  private PduPart getPduPartSkeleton(String contentType) {
    PduPart part = new PduPart();
    part.setContentType(contentType.getBytes());
    part.setDataUri(Uri.EMPTY);
    return part;
  }
}
