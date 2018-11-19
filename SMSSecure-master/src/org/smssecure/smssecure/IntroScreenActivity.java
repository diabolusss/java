package org.smssecure.smssecure;

import android.annotation.TargetApi;
import android.app.Notification;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.graphics.drawable.ColorDrawable;
import android.os.Build;
import android.os.Build.VERSION_CODES;
import android.os.Bundle;
import android.support.annotation.NonNull;
import android.support.annotation.StringRes;
import android.support.v4.app.NotificationCompat;
import android.support.v4.view.ViewPager;
import android.util.Log;
import android.view.View;
import android.view.View.OnClickListener;

import com.melnykov.fab.FloatingActionButton;
import com.nineoldandroids.animation.ArgbEvaluator;

import org.smssecure.smssecure.IntroPagerAdapter.IntroPage;
import org.smssecure.smssecure.util.ServiceUtil;
import org.smssecure.smssecure.util.SMSSecurePreferences;
import org.smssecure.smssecure.util.Util;
import org.smssecure.smssecure.util.ViewUtil;
import org.whispersystems.libaxolotl.util.guava.Optional;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import me.relex.circleindicator.CircleIndicator;

public class IntroScreenActivity extends BaseActionBarActivity {
  private static final String TAG = IntroScreenActivity.class.getSimpleName();

  private enum IntroScreen {
    INTRO(new ArrayList<IntroPage>() {
      {
        add(new IntroPage(0xFF7568AE,
                          BasicIntroFragment.newInstance(R.drawable.splash_logo,
                                                         R.string.IntroScreenActivity_welcome_to_smssecure,
                                                         R.string.IntroScreenActivity_smssecure_description)));
        add(new IntroPage(0xFF7568AE,
                          BasicIntroFragment.newInstance(R.drawable.splash_padlock,
                                                         R.string.IntroScreenActivity_encrypt_your_messages,
                                                         R.string.IntroScreenActivity_encrypt_your_messages_description)));
        add(new IntroPage(0xFF7568AE,
                         BasicIntroFragment.newInstance(R.drawable.splash_open_padlock,
                                                        R.string.IntroScreenActivity_talk_to_everyone,
                                                        R.string.IntroScreenActivity_talk_to_everyone_description)));
      }
    });

    private List<IntroPage> pages;

    IntroScreen(@NonNull List<IntroPage> pages) {
      this.pages = pages;
    }

    IntroScreen(@NonNull IntroPage page)
    {
      this(Collections.singletonList(page));
    }

    public List<IntroPage> getPages() {
      return pages;
    }

    public IntroPage getPage(int i) {
      return pages.get(i);
    }
  }

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);

    Optional<IntroScreen> introScreen = getIntroScreen(this);
    if (!introScreen.isPresent()) {
      onContinue();
      return;
    }

    setContentView(R.layout.splash_screen_activity);
    final ViewPager            pager     = ViewUtil.findById(this, R.id.pager);
    final CircleIndicator      indicator = ViewUtil.findById(this, R.id.indicator);
    final FloatingActionButton fab       = ViewUtil.findById(this, R.id.fab);

    pager.setAdapter(new IntroPagerAdapter(getSupportFragmentManager(), introScreen.get().getPages()));

    final int numberOfPages = introScreen.get().getPages().size();
    if (numberOfPages > 1) {
      indicator.setViewPager(pager);
      indicator.setOnPageChangeListener(new OnPageChangeListener(introScreen.get()));
    } else {
      indicator.setVisibility(View.GONE);
    }

    fab.setOnClickListener(new OnClickListener() {
      @Override
      public void onClick(View v) {
        Log.w(TAG, "getCurrentItem(): "+pager.getCurrentItem());
        if (pager.getCurrentItem()+1 == numberOfPages){
          onContinue();
        } else {
          pager.setCurrentItem(pager.getCurrentItem()+1, true);
        }
      }
    });

    getWindow().setBackgroundDrawable(new ColorDrawable(introScreen.get().getPage(0).backgroundColor));
    setStatusBarColor(introScreen.get().getPage(0).backgroundColor);
  }

  @TargetApi(VERSION_CODES.LOLLIPOP)
  private void setStatusBarColor(int color) {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
      getWindow().setStatusBarColor(color);
    }
  }

  private void onContinue() {
    SMSSecurePreferences.setFirstRun(this);
    startActivity((Intent)getIntent().getParcelableExtra("next_intent"));
    finish();
  }

  public static Optional<IntroScreen> getIntroScreen(Context context) {
    if (!SMSSecurePreferences.isFirstRun(context)) return Optional.absent();

    Optional<IntroScreen> introScreen = Optional.absent();
    for (IntroScreen screen : IntroScreen.values()) {
      introScreen = Optional.of(screen);
    }

    return introScreen;
  }

  private final class OnPageChangeListener implements ViewPager.OnPageChangeListener {
    private final ArgbEvaluator evaluator = new ArgbEvaluator();
    private final IntroScreen   introScreen;

    public OnPageChangeListener(IntroScreen introScreen) {
      this.introScreen = introScreen;
    }

    @Override
    public void onPageSelected(int position) {}

    @Override
    public void onPageScrollStateChanged(int state) {}

    @Override
    public void onPageScrolled(int position, float positionOffset, int positionOffsetPixels) {
      final int nextPosition = (position + 1) % introScreen.getPages().size();

      final int color = (Integer)evaluator.evaluate(positionOffset,
                                                    introScreen.getPage(position).backgroundColor,
                                                    introScreen.getPage(nextPosition).backgroundColor);
      getWindow().setBackgroundDrawable(new ColorDrawable(color));
      setStatusBarColor(color);
    }
  }
}
